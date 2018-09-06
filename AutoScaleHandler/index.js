'use strict';

// TODO: where to store this master key?
let ___request_uuid;
const masterKey = process.env.REST_API_MASTER_KEY;
const databaseName = 'fortigateInstances';
const dbCollectionMonitored = 'instances';
const dbCollectionMaster = 'masterPool';
const dbCollectionMutex = 'mutex';

const request = require('request');
const crypto = require('crypto');
const uuidv5 = require('uuid/v5');
const MsRest = require('ms-rest-azure');
/**
 * Here are a few global functions to handle Azure RESTful API
 */

/**
 * A unified logger class to handle logging across different platforms.
 */
class Logger {
    constructor(loggerObject) {
        this.logger = loggerObject;
    }

    /**
     * control logging output level.
     * @param {Object} levelObject {log: true | false, info: true | false, warn: true | false,
     *  error: true | false}
     */
    setLoggingLevel(levelObject) {
        this.level = levelObject;
    }

    /**
     * output information to a regular logging stream.
     * @param {Object | String} object information to log
     */
    log(object) {} // eslint-disable-line no-unused-vars
    /**
     * output information to the info logging stream.
     * @param {Object | String} object information to log
     */
    info(object) {} // eslint-disable-line no-unused-vars
    /**
     * output information to the warning logging stream.
     * @param {Object | String} object information to log
     */
    warn(object) {} // eslint-disable-line no-unused-vars
    /**
     * output information to the error logging stream.
     * @param {Object | String} object information to log
     */
    error(object) {} // eslint-disable-line no-unused-vars
}

var logger = new Logger();


const uuidGenerator = function(inStr) {
    return uuidv5(inStr, uuidv5.URL);
};

function sleep(ms) {
    return new Promise(resolve => {
        logger.warn(`sleep for ${ms} ms`);
        setTimeout(resolve, ms);
    });
}

function getAzureArmClient() {
    var _credentials, _token, _subscription;
    /**
     * will throw error if there is any.
     * @param {String} url url to fetch resource
     * @returns {Promise} a promise
     */
    function AzureArmGet(url) {
        return new Promise((resolve, reject) => {
            logger.info(`calling AzureArmGet url: ${url}`);
            request.get({
                url: url,
                headers: {
                    Authorization: `Bearer ${_token}`
                }
            }, function(error, response, body) {
                // TODO: handle error.
                if (error) {
                    logger.error(`called AzureArmGet but returned unknown error ${JSON.stringify(error)}`); // eslint-disable-line max-len
                    reject(error);
                } else {
                    if (response.statusCode === 200) {
                        resolve(body);
                    } else {
                        logger.error(`called AzureArmGet but returned error (code: ${response.statusCode}) ${response.body}`); // eslint-disable-line max-len
                        reject(response);
                    }
                }
            });
        });
    }

    /**
     * Get a resource by a given id (aka: the full path of an ARM)
     * this function doesn't do error handling. The caller must do error handling.
     * @param {String} resourceId resource Id
     * @param {String} apiVersion a proper api version string
     */
    async function getResource(resourceId, apiVersion) {
        const url =
            `https://management.azure.com${resourceId}?api-version=${apiVersion}`;
        let response = await AzureArmGet(url);
        return JSON.parse(response);
    }

    /**
     * Fetch a network interface from ARM
     * @param {String} resourceId the resource id of network interface
     */
    async function getNetworkInterface(resourceId) {
        try {
            logger.info('calling getNetworkInterface.');
            let response = await getResource(resourceId, '2017-12-01');
            let body = JSON.parse(response.body);
            logger.info('called getNetworkInterface.');
            return body;
        } catch (error) {
            logger.error(`getNetworkInterface > error ${JSON.stringify(error)}`);
        }
        return null;
    }

    /**
     * List all virtualmachines of a scale set in a resource group, from ARM.
     * @param {String} resourceGroup the resource group id
     * @param {String} scaleSetName the scale set name
     */
    async function listVirtualMachines(resourceGroup, scaleSetName) {
        let resourceId = `/subscriptions/${_subscription}/resourceGroups/${resourceGroup}/providers/Microsoft.Compute/virtualMachineScaleSets/${scaleSetName}/virtualMachines`; // eslint-disable-line max-len
        try {
            logger.info('calling listVirtualMachines.');
            let response = await getResource(resourceId, '2017-12-01');
            logger.info('called listVirtualMachines.');
            return response.value;
        } catch (error) {
            logger.error(`listVirtualMachines > error ${JSON.stringify(error)}`);
            return [];
        }
    }

    /**
     * Get a virtual machine, including its network interface details
     * @param {String} resourceGroup resource group id
     * @param {String} scaleSetName scale set name
     * @param {String} virtualMachineId virtualmachine id
     */
    async function getVirtualMachine(resourceGroup, scaleSetName, virtualMachineId) {
        let resourceId = `/subscriptions/${_subscription}/resourceGroups/${resourceGroup}/providers/Microsoft.Compute/virtualMachineScaleSets/${scaleSetName}/virtualMachines/${virtualMachineId}`; // eslint-disable-line max-len
        try {
            let virtualMachine = await getResource(resourceId, '2017-12-01'),
                networkInterfaces = await getResource(`${resourceId}/networkInterfaces`, '2017-12-01'); // eslint-disable-line max-len
            virtualMachine.properties.networkProfile.networkInterfaces = networkInterfaces.value;
            return virtualMachine;
        } catch (error) {

        }
    }

    /**
     * This lookup takes longer time to complete. a few round of http requests require.
     * can we optimize to reduce this ?
     * @param {String} resourceGroup resource group id
     * @param {String} scaleSetName scale set name
     * @param {String} ip primary ip address of an instance
     */
    async function getVirtualMachineByIp(resourceGroup, scaleSetName, ip) {
        logger.info('calling getVirtualMachineByIp.');
        let found = {},
            virtualMachines = await listVirtualMachines(resourceGroup, scaleSetName);
        for (let vm of virtualMachines.value) {
            try {
                let nic = await getResource(vm.properties.id, '2017-12-01');
                let vmIp = nic.properties.ipConfigurations[0].properties.privateIPAddress;
                if (ip === vmIp) {
                    found = {
                        virtualMachine: vm,
                        networkInterface: nic
                    };
                    break;
                }
            } catch (error) {
                logger.warn(`getVirtualMachineByIp > error querying for networkInterface: ${JSON.stringify(error)}`); // eslint-disable-line max-len
            }
        }
        logger.info('called getVirtualMachineByIp.');
        return found;
    }

    /* eslint-disable max-len */
    /**
     * Do authentication and authorization with Azure Service Principal for this client and store
     * in the client class.
     * @see https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-create-service-principal-portal
     * @param {String} app_id the application id
     * @param {String} app_secret the application secret
     * @param {String} tenant_id the tenant id (aka: Active Directory > directory id)
     * @returns {Promise} a promise
     */
    /* eslint-enable max-len */
    function authWithServicePrincipal(app_id, app_secret, tenant_id) {
        return new Promise(function(resolve, reject) {
            logger.info('calling authWithServicePrincipal.');
            MsRest.loginWithServicePrincipalSecret(app_id, app_secret, tenant_id,
                (error, credentials) => {
                    if (error) {
                        logger.error(`authWithServicePrincipal > error: ${JSON.stringify(error)}`);
                        reject(error);
                    }
                    _credentials = credentials.tokenCache._entries[0];
                    _token = _credentials.accessToken;
                    logger.info('called authWithServicePrincipal.');
                    resolve(true);
                });
        });
    }

    return {
        authWithServicePrincipal: authWithServicePrincipal,
        useSubscription: function(subscription) {
            _subscription = subscription;
        },
        ComputeClient: {
            VirtualMachineScaleSets: {
                getNetworkInterface: getNetworkInterface,
                getVirtualMachineByIp: getVirtualMachineByIp,
                listVirtualMachines: listVirtualMachines,
                getVirtualMachine: getVirtualMachine
            }
        }
    };
}

function getAuthorizationTokenUsingMasterKey(verb, resourceType, resourceId, date, _masterKey) {
    var key = new Buffer(_masterKey, 'base64');

    var text = `${(verb || '').toLowerCase()}\n${
        (resourceType || '').toLowerCase()}\n${
        resourceId || ''}\n${
        date.toLowerCase()}\n` +
        '' + '\n';

    var body = new Buffer(text, 'utf8');
    var signature = crypto.createHmac('sha256', key).update(body).digest('base64');

    var MasterToken = 'master';

    var TokenVersion = '1.0';

    return encodeURIComponent(`type=${MasterToken}&ver=${TokenVersion}&sig=${signature}`);
}

function azureApiCosmosDBCreateDB(dbAccount, dbName, _masterKey) {
    return new Promise(function(resolve, reject) {
        logger.info('calling azureApiCosmosDBCreateDB.');
        let date = (new Date()).toUTCString();
        let token = getAuthorizationTokenUsingMasterKey('post', 'dbs', '', date, _masterKey);
        let path = `https://${dbAccount}.documents.azure.com/dbs`;
        let headers = {
            Authorization: token,
            'x-ms-version': '2017-02-22',
            'x-ms-date': date
        };
        request.post({
            url: path,
            headers: headers,
            body: {
                id: dbName
            },
            json: true
        }, function(error, response, body) { // eslint-disable-line no-unused-vars
            if (error) {
                logger.error(`called azureApiCosmosDBCreateDB > unknown error: ${JSON.stringify(response)}`); // eslint-disable-line max-len
                reject(error);
            } else if (response.statusCode === 201) {
                logger.info(`called azureApiCosmosDBCreateDB: ${dbName} created.`);
                resolve(true);
            } else if (response.statusCode === 409) {
                logger.warn(`called azureApiCosmosDBCreateDB: not created, ${dbName} already exists.`); // eslint-disable-line max-len
                resolve(false); // db exists.
            } else {
                logger.error(`called azureApiCosmosDBCreateDB > other error: ${JSON.stringify(response)}`); // eslint-disable-line max-len
                reject(response);
            }
        });
    });
}

function azureApiCosmosDBCreateCollection(dbAccount, dbName, collectionName, _masterKey) {
    return new Promise(function(resolve, reject) {
        logger.info('calling azureApiCosmosDBCreateCollection.');
        let date = (new Date()).toUTCString();
        let token = getAuthorizationTokenUsingMasterKey('post',
            'colls', `dbs/${dbName}`, date, _masterKey);
        let path = `https://${dbAccount}.documents.azure.com/dbs/${dbName}/colls`;
        let headers = {
            Authorization: token,
            'x-ms-version': '2017-02-22',
            'x-ms-date': date
        };
        request.post({
            url: path,
            headers: headers,
            body: {
                id: collectionName
            },
            json: true
        }, function(error, response, body) { // eslint-disable-line no-unused-vars
            if (error) {
                logger.error(`called azureApiCosmosDBCreateCollection > unknown error: ${JSON.stringify(response)}`); // eslint-disable-line max-len
                reject(error);
            } else if (response.statusCode === 201) {
                logger.info(`called azureApiCosmosDBCreateCollection: ${dbName}/${collectionName} created.`); // eslint-disable-line max-len
                resolve(true);
            } else if (response.statusCode === 409) {
                logger.warn(`called azureApiCosmosDBCreateCollection: not created, ${dbName}/${collectionName} already exists.`); // eslint-disable-line max-len
                resolve(false); // db exists.
            } else {
                logger.error(`called azureApiCosmosDBCreateCollection > other error: ${JSON.stringify(response)}`); // eslint-disable-line max-len
                reject(response);
            }
        });
    });
}

function azureApiCosmosDBCreateDocument(dbAccount, dbName, collectionName, documentId, documentContent, replaced, _masterKey) { // eslint-disable-line max-len
    return new Promise(function(resolve, reject) {
        logger.info('calling azureApiCosmosDBCreateDocument.');
        if (!(dbName && collectionName && documentId)) {
            // TODO: what should be returned from here?
            reject(null);
        }
        let date = (new Date()).toUTCString();
        let token = getAuthorizationTokenUsingMasterKey('post',
            'docs', `dbs/${dbName}/colls/${collectionName}`, date, _masterKey);
        let path = `https://${dbAccount}.documents.azure.com/dbs/${dbName}/colls/${collectionName}/docs`; // eslint-disable-line max-len
        let headers = {
            Authorization: token,
            'x-ms-version': '2017-02-22',
            'x-ms-date': date
        };
        if (replaced) {
            headers['x-ms-documentdb-is-upsert'] = true;
        }
        let content = documentContent || {};
        content.id = documentId;
        try {
            JSON.stringify(content);
        } catch (error) {
            // TODO: what should be returned from here?
            reject(null);
        }
        request.post({
            url: path,
            headers: headers,
            body: content,
            json: true
        }, function(error, response, body) {
            if (error) {
                logger.error(`called azureApiCosmosDBCreateDocument > unknown error: ${JSON.stringify(response)}`); // eslint-disable-line max-len
                reject(error);
            } else if (response.statusCode === 200) {
                logger.info(`called azureApiCosmosDBCreateDocument: ${dbName}/${collectionName}/${documentId} not modified.`); // eslint-disable-line max-len
                resolve(body);
            } else if (response.statusCode === 201) {
                logger.info(`called azureApiCosmosDBCreateDocument: ${dbName}/${collectionName}/${documentId} created.`); // eslint-disable-line max-len
                resolve(body);
            } else if (response.statusCode === 409) {
                logger.warn(`called azureApiCosmosDBCreateDocument: not created, ${dbName}/${collectionName}/${documentId} already exists.`); // eslint-disable-line max-len
                resolve(null); // document with such id exists.
            } else {
                logger.error(`called azureApiCosmosDBCreateDocument > other error: ${JSON.stringify(response)}`); // eslint-disable-line max-len
                reject(response);
            }
        });
    });
}

function azureApiCosmosDBDeleteDocument(dbAccount, dbName, collectionName, documentId, _masterKey) {
    return new Promise(function(resolve, reject) {
        logger.info('calling azureApiCosmosDBDeleteDocument.');
        if (!(dbName && collectionName && documentId)) {
            // TODO: what should be returned from here?
            reject(null);
        }
        let date = (new Date()).toUTCString();
        let token = getAuthorizationTokenUsingMasterKey('delete',
            'docs', `dbs/${dbName}/colls/${collectionName}/docs/${documentId}`, date, _masterKey);
        let path = `https://${dbAccount}.documents.azure.com/dbs/${dbName}/colls/${collectionName}/docs/${documentId}`; // eslint-disable-line max-len
        let headers = {
            Authorization: token,
            'x-ms-version': '2017-02-22',
            'x-ms-date': date
        };
        request.delete({
            url: path,
            headers: headers
        }, function(error, response, body) { // eslint-disable-line no-unused-vars
            if (error) {
                logger.error(`called azureApiCosmosDBDeleteDocument > unknown error: ${JSON.stringify(response)}`); // eslint-disable-line max-len
                reject(error);
            } else if (response.statusCode === 204) {
                logger.info(`called azureApiCosmosDBDeleteDocument: ${dbName}/${collectionName}/${documentId} deleted.`); // eslint-disable-line max-len
                resolve(true);
            } else if (response.statusCode === 404) {
                logger.warn(`called azureApiCosmosDBDeleteDocument: not deleted, ${dbName}/${collectionName}/${documentId} not found.`); // eslint-disable-line max-len
                resolve(false); // document with such id exists.
            } else {
                logger.error(`called azureApiCosmosDBDeleteDocument > other error: ${JSON.stringify(response)}`); // eslint-disable-line max-len
                reject(response);
            }
        });
    });
}

/**
 * fire a CosmosDB query
 * @param {String} dbAccount DB account
 * @param {Object} resource  object {dbName, collectionName, queryObject}
 * @param {String} _masterKey the authorization token for db operations
 * @returns {Promise} a promise
 */
function azureApiCosmosDbQuery(dbAccount, resource, _masterKey) {
    return new Promise((resolve, reject) => {
        logger.info('calling azureApiCosmosDbQuery.');
        let date = (new Date()).toUTCString();
        let resourcePath = '',
            resourceType = '';
        if (resource.dbName !== undefined) {
            resourceType = 'dbs';
            resourcePath += `dbs/${resource.dbName}`;
        }
        if (resource.collectionName !== undefined) {
            if (resource.dbName === undefined) {
                // TODO: what should return by this reject?
                logger.error(`called azureApiCosmosDbQuery: invalid resource ${JSON.stringify(resource)}`); // eslint-disable-line max-len
                reject({});
                return;
            }
            resourceType = 'colls';
            resourcePath += `/colls/${resource.collectionName}`;
        }
        resourceType = 'docs';
        // resourcePath += `/docs`;

        let token = getAuthorizationTokenUsingMasterKey('post',
            resourceType, resourcePath, date, _masterKey);
        let path = `https://${dbAccount}.documents.azure.com/${resourcePath}/docs`;
        let headers = {
            Authorization: token,
            'x-ms-version': '2017-02-22',
            'x-ms-date': date,
            'x-ms-documentdb-isquery': 'True',
            'Content-Type': 'application/query+json'
        };
        if (resource.partitioned) {
            headers['x-ms-documentdb-query-enablecrosspartition'] = true;
            if (resource.partitionkey) {
                headers['x-ms-documentdb-partitionkey'] = resource.partitionkey;
            }
        }
        let body = '';
        try {
            body = JSON.stringify({
                query: resource.queryObject.query,
                parameters: resource.queryObject.parameters || []
            });
        } catch (error) {
            // TODO: what should return by this reject?
            logger.error(`called azureApiCosmosDbQuery: invalid queryObject -> ${JSON.stringify(resource.queryObject)}.`); // eslint-disable-line max-len
            reject({});
        }
        request.post({
            url: path,
            headers: headers,
            body: body
        }, function(error, response, _body) { // eslint-disable-line no-unused-vars
            if (error) {
                logger.error(`called azureApiCosmosDbQuery > unknown error: ${JSON.stringify(response)}`); // eslint-disable-line max-len
                reject(error);
            } else if (response.statusCode === 200) {
                logger.info(`azureApiCosmosDbQuery: ${resourcePath} retrieved.`);
                try {
                    let res = JSON.parse(response.body);
                    logger.info('called azureApiCosmosDbQuery.');
                    resolve(res.Documents);
                } catch (err) {
                    logger.warn('called azureApiCosmosDbQuery: Documents object parsed failed.');
                    // TODO: what should return if failed to parse the documents?
                    reject({});
                }
            } else if (response.statusCode === 304) {
                logger.warn(`called azureApiCosmosDbQuery: ${resourcePath} not modified. return empty response body.`); // eslint-disable-line max-len
                reject(response);
            } else if (response.statusCode === 404) {
                logger.warn(`called azureApiCosmosDbQuery: not found, ${resourcePath} was deleted.`); // eslint-disable-line max-len
                reject(response);
            } else {
                logger.error(`called azureApiCosmosDbQuery > other error: ${JSON.stringify(response)}`); // eslint-disable-line max-len
                reject(response);
            }
        });
    });
}


module.exports = async function(context, req) {
    ___request_uuid = uuidGenerator(JSON.stringify(req));
    let _modules = initModules();
    // override the global logger object within this script
    logger = new(_modules.azurePlatformLogger)(context.log);
    // logger.setLoggingLevel({log: false, info: false, warn: false, error: false});// no logging
    await new(_modules.AzureAutoscaleHander)().handle(context, req);
};

/**
 * Emulate a module system so we can split this into multiple files later.
 * @TODO: separate into actual separate module files.
 * @returns {Object} modules
 */
function initModules() {
    const modules = {};
    modules.AutoscaleHandler = getAutoscaleHandler();
    modules.LifecycleItem = getLifecycleItem();
    modules.CloudPlatform = getCloudPlatform();
    modules.AzurePlatform = getAzurePlatform(modules.CloudPlatform, modules.LifecycleItem);
    modules.AzureAutoscaleHander = getAzureAutoscaleHandler(
        modules.AzurePlatform, modules.AutoscaleHandler, modules.LifecycleItem
    );
    modules.azurePlatformLogger = getAzurePlatformLogger();
    return modules;

    function getCloudPlatform() {
        /**
         * @abstract
         * Class used to define the capabilities required from cloud platform.
         */
        return class CloudPlatform {
            throwNotImplementedException() {
                throw new Error('Not Implemented');
            }
            /* eslint-disable no-unused-vars */
            /**
             * Initialize (and wait for) any required resources such as database tables etc.
             * Abstract class method.
             */
            async init() {
                await this.throwNotImplementedException();
            }

            /**
             * Submit an election vote for this ip address to become the master.
             * Abstract class method.
             * @param {String} ip Ip of the fortigate which wants to become the master
             * @param {String} purgeMasterIp Ip of the dead master we should purge before voting
             */
            async putMasterElectionVote(ip, purgeMasterIp) {
                await this.throwNotImplementedException();
            }
            /**
             * Get the ip address which won the master election.
             * Abstract class method.
             * @returns {String} Ip of the fortigate which should be the auto-sync master
             */
            async getElectedMaster() {
                await this.throwNotImplementedException();
            }
            /**
             * Get an existing lifecyle action from the database.
             * Abstract class method.
             * @param {String} instanceId Instance ID of a fortigate.
             * @returns {LifecycleItem} Item used by the platform to complete a lifecycleAction.
             */
            async getPendingLifecycleAction(instanceId) {
                await this.throwNotImplementedException();
            }
            /**
             * Put a new lifecycle action into the database.
             * Abstract class method.
             * @param {LifecycleItem} item Item used by the platform to complete
             *  a lifecycleAction.
             */
            async putPendingLifecycleAction(item) {
                await this.throwNotImplementedException();
            }
            /**
             * Clean up database the current database entry (or any expired entries).
             * Abstract class method.
             * @param {LifecycleItem} [item] Item used to complete a lifecycle
             *  action. When provided, only this item will be cleaned up, otherwise scan for expired
             *  items to purge.
             */
            async cleanUpDb(item = null) {
                await this.throwNotImplementedException();
            }
            /**
             * Get the url for the callback-url portion of the config.
             * Abstract class method.
             * @param {Object} fromContext a context object to get the url, if needed.
             */
            async getCallbackEndpointUrl(fromContext = null) {
                await this.throwNotImplementedException();
            }

            /**
             * Lookup the instanceid using an ip address.
             * Abstract class method.
             * @param {String} ip Local ip address of an instance.
             */
            async findInstanceIdByIp(ip) {
                await this.throwNotImplementedException();
            }

            /**
             * Lookup the instanceid using an id.
             * Abstract class method.
             * @param {String} id unique id of an instance.
             */
            async findInstanceIdById(id) {
                await this.throwNotImplementedException();
            }

            /**
             * Protect an instance from being scaled out.
             * Abstract class method.
             * @param {LifecycleItem} item Item that was used by the platform to complete a
             *  lifecycle action
             * @param {boolean} [protect=true] Whether to add or remove or protection the instance.
             */
            async protectInstanceFromScaleIn(item, protect = true) {
                await this.throwNotImplementedException();
            }

            /**
             * List all instances with given parameters.
             * Abstract class method.
             * @param {Object} parameters parameters necessary for listing all instances.
             */
            async listAllInstances(parameters) {
                await this.throwNotImplementedException();
            }

            /**
             * Describe an instance and retrieve its information, with given parameters.
             * Abstract class method.
             * @param {Object} parameters parameters necessary for describing an instance.
             */
            async describeInstance(parameters) {
                await this.throwNotImplementedException();
            }

            /**
             * do the instance health check.
             * Abstract class method.
             * @param {Object} instance the platform-specific instance object
             * @param {Number} heartBeatInterval the expected interval (second) between heartbeats
             * @returns {Object}
             *      {healthy: true | false, heartBeatLostCount: <int>, nextHeartBeatTime: <int>}
             */
            async getInstanceHealthCheck(instance, heartBeatInterval) {
                await this.throwNotImplementedException();
            }

            /**
             * Delete one or more instances from the auto scaling group.
             * Abstract class method.
             * @param {Object} parameters parameters necessary for instance deletion.
             */
            async deleteInstances(parameters) {
                await this.throwNotImplementedException();
            }

            /**
             * return a platform-specific logger class
             */
            getPlatformLogger() {
                this.throwNotImplementedException();
            }
            /* eslint-enable no-unused-vars */
        };
    }

    // eslint-disable-next-line no-unused-vars
    function getAzureAutoscaleHandler(AzurePlatform, AutoscaleHandler, LifecycleItem) {
        /**
         * Implementation of the AutoscaleHandler for handling requests into the Azure function
         * serverless implementation.
         */
        return class AzureAutoscaleHandler extends AutoscaleHandler {
            constructor() {
                const baseConfig = process.env.FTGT_BASE_CONFIG.replace(/\\n/g, '\n');
                super(new AzurePlatform(), baseConfig);
                this._electionLock = null;
                this._selfInstance = null;
            }

            async handle(context, req) {
                // let x = require(require.resolve(`${process.cwd()}/azure-arm-client`));
                logger.info('start to handle autoscale');
                context.log.info(`incoming request: ${JSON.stringify(req)}`);
                let response;
                try {
                    await this.init();
                    // handle get config
                    response = await this._handleGetConfig(req);
                    logger.info(response);

                } catch (error) {
                    context.log.error(error.stack);
                    response = error.message;
                }
                context.res = {
                    // status: 200, /* Defaults to 200 */
                    headers: {
                        'Content-Type': 'text/plain'
                    },
                    body: response
                };
            }

            async _handleGetConfig(_request) {
                logger.info('calling handleGetConfig');
                let parameters,
                    masterInfo,
                    masterIsHealthy = false,
                    isNewInstance = false,
                    selfHealthCheck,
                    masterHealthCheck,
                    callingInstanceId = this.getCallingInstanceId(_request),
                    heartBeatInterval = this.getHeartBeatInterval(_request),
                    counter = 0,
                    nextTime,
                    endTime,
                    virtualMachine;

                // verify the caller (diagram: trusted source?)
                if (callingInstanceId) {
                    virtualMachine = await this.platform.findInstanceIdById(callingInstanceId);
                }
                if (!callingInstanceId || !virtualMachine) {
                    // not trusted
                    throw new Error(`Unauthorized calling instance (vmid: ${callingInstanceId}). Instance not found in scale set.`);// eslint-disable-line max-len
                }

                // describe self
                parameters = {
                    resourceGroup: process.env.RESOURCE_GROUP,
                    scaleSetName: process.env.SCALESET_NAME,
                    virtualMachineId: virtualMachine.instanceId
                };
                this._selfInstance = await this.platform.describeInstance(parameters);

                // is myself under health check monitoring?
                // do self health check
                selfHealthCheck = await this.platform.getInstanceHealthCheck({
                    vmId: this._selfInstance.properties.vmId
                }, heartBeatInterval);
                // not monitored instance?
                if (!selfHealthCheck) {
                    isNewInstance = true;
                    // save self to monitored instances db (diagram: add instance to monitor)
                    await this.addInstanceToMonitor(this._selfInstance,
                        Date.now() + heartBeatInterval * 1000);
                }

                nextTime = Date.now();
                endTime = nextTime + 10000; // unit ms

                // (diagram: master exists?)
                while (!masterIsHealthy && (nextTime < endTime)) {
                    // get the current master
                    masterInfo = await this.getMasterInfo();

                    // is master healthy?
                    if (masterInfo) {
                        // self is master?
                        if (masterInfo.ip === this._selfInstance.getPrimaryPrivateIp()) {
                            masterHealthCheck = selfHealthCheck;
                        } else {
                            masterHealthCheck =
                                await this.platform.getInstanceHealthCheck(masterInfo,
                                    heartBeatInterval);
                        }
                        masterIsHealthy = !!masterHealthCheck && masterHealthCheck.healthy;
                    }

                    // we need a new master! let's hold a master election!
                    if (!masterIsHealthy) {
                        // but can I run the election? (diagram: anyone's holding master election?)
                        this._electionLock = await this.AcquireMutex(dbCollectionMaster);
                        if (this._electionLock) {
                            // yes, you run it!
                            logger.info('This thread is running an election.');
                            try {
                                // (diagram: elect new master from queue (existing instances))
                                await this.holdMasterElection(
                                    this._selfInstance.getPrimaryPrivateIp());
                                logger.info('Election completed.');
                            } catch (error) {
                                logger.error('Something went wrong in the master election.');
                            } finally {
                                // release the lock, let someone else run the election.
                                await this.releaseMutex(dbCollectionMaster, this._electionLock);
                                this._electionLock = null;
                            }
                            // (diagram: master exists?)
                            masterInfo = await this.getMasterInfo();
                        } else {
                            logger.info(`Wait for master election (counter: ${++counter}, time:${Date.now()})`); // eslint-disable-line max-len
                        }
                    }
                    nextTime = Date.now();
                    masterIsHealthy = !!masterInfo;
                    if (!masterIsHealthy) {
                        await sleep(1000); // (diagram: wait for a moment (interval))
                    }
                }

                // (diagram: am I a new instance?)
                // I am under monitor, please verify my periodic health check!
                if (!isNewInstance) {
                    // if still healthy or unhealthy records are less than
                    // process.env.HEARTBEAT_LOSS_COUNT, can claim healthy again
                    // (diagram: heartbeats lost previously? & diagram: loss acceptable?)
                    if (selfHealthCheck.healthy ||
                        (!selfHealthCheck.healthy &&
                            selfHealthCheck.heartBeatLostCount <
                            process.env.HEART_BEAT_LOSS_COUNT)) {
                        // may long live! (diagram: Mark instance healthy)
                        await this.updateInstanceToMonitor({
                            vmId: this._selfInstance.properties.vmId
                        });
                    } else { // cannot claim healthy any more, start a new life in heaven.
                        // (diagram: remove instance)
                        await this.removeInstance({
                            vmId: this._selfInstance.properties.vmId
                        });
                    }
                }
                // the master ip same as mine? (diagram: master IP same as mine?)
                if (masterInfo.ip === this._selfInstance.getPrimaryPrivateIp()) {
                    // am I a new instance? (diagram: am I new instance?)
                    if (isNewInstance) {
                        logger.info(`called handleGetConfig: returning master config(master-ip: ${masterInfo.ip})`); // eslint-disable-line max-len
                        return await this.getMasterConfig(
                            await this.platform.getCallbackEndpointUrl(_request));
                    } else {
                        logger.info(`called handleGetConfig: respond to master heartbeat(master-ip: ${masterInfo.ip})`); // eslint-disable-line max-len
                        return this.responseToHeartBeat(masterInfo.ip);
                    }
                } else {
                    // am I a new instance? (diagram: am I new instance?)
                    if (isNewInstance) {
                        logger.info(`called handleGetConfig: returning slave config(master-ip: ${masterInfo.ip})`); // eslint-disable-line max-len
                        return await this.getSlaveConfig(masterInfo.ip,
                            await this.platform.getCallbackEndpointUrl(_request));
                    } else {
                        logger.info(`called handleGetConfig: respond to slave heartbeat(master-ip: ${masterInfo.ip})`); // eslint-disable-line max-len
                        return this.responseToHeartBeat(masterInfo.ip);
                    }
                }
            }

            async holdMasterElection(ip) { // eslint-disable-line no-unused-vars
                // list all election candidates
                let parameters = {
                    resourceGroup: process.env.RESOURCE_GROUP,
                    scaleSetName: process.env.SCALESET_NAME
                };
                let virtualMachine, candidate, candidates = [];
                let [virtualMachines, moniteredInstances] = await Promise.all([
                    this.platform.listAllInstances(parameters),
                    this.listMonitoredInstances()
                ]);
                for (virtualMachine of virtualMachines) {
                    // if candidate is monitored, and it is in the healthy state
                    // put in in the candidate pool
                    if (moniteredInstances[virtualMachine.instanceId] !== undefined) {
                        let healthCheck = await this.platform.getInstanceHealthCheck(
                            moniteredInstances[virtualMachine.instanceId], -1
                        );
                        if (healthCheck.healthy &&
                            virtualMachine.properties.provisioningState === 'Succeeded') {
                            candidates.push(virtualMachine);
                        }
                    }
                }

                let instanceId = 0,
                    master = null;
                let promiseAllArray = [],
                    candidateDescribingFunc = async _candidate => {
                        let _parameters = {
                            resourceGroup: process.env.RESOURCE_GROUP,
                            scaleSetName: process.env.SCALESET_NAME,
                            virtualMachineId: _candidate.instanceId
                        };
                        return await this.platform.describeInstance(_parameters);
                    };
                if (candidates.length > 0) {
                    // choose the one with smaller instanceId
                    for (candidate of candidates) {
                        if (instanceId === 0 || candidate.instanceId < instanceId) {
                            instanceId = candidate.instanceId;
                            master = candidate;
                        }
                        promiseAllArray.push((candidateDescribingFunc)(candidate));
                    }

                    if (promiseAllArray.length > 0) {
                        candidates = await Promise.all(promiseAllArray);
                    }
                    // monitor all candidates
                    promiseAllArray = [];
                    for (candidate of candidates) {
                        promiseAllArray.push((this.addInstanceToMonitor)(candidate));
                    }
                    await Promise.all(promiseAllArray);
                }

                if (master) {
                    parameters = {
                        resourceGroup: process.env.RESOURCE_GROUP,
                        scaleSetName: process.env.SCALESET_NAME,
                        virtualMachineId: instanceId
                    };
                    virtualMachine = await this.platform.describeInstance(parameters);
                    return await this.updateMaster(virtualMachine);
                } else {
                    return Promise.reject('No instance available for master.');
                }
            }

            async updateMaster(instance) {
                logger.info('calling updateMaster');
                let documentContent = {
                    master: 'master',
                    ip: instance.getPrimaryPrivateIp(),
                    instanceId: instance.instanceId,
                    vmId: instance.properties.vmId
                };

                let documentId = `${process.env.SCALESET_NAME}-master`,
                    replaced = true;
                try {
                    let doc = await azureApiCosmosDBCreateDocument(process.env.SCALESET_DB_ACCOUNT,
                        databaseName, dbCollectionMaster, documentId, documentContent, replaced,
                        masterKey);
                    if (doc) {
                        logger.info(`called updateMaster: master(id:${documentContent.instanceId}, ip: ${documentContent.ip}) updated.`); // eslint-disable-line max-len
                        return true;
                    } else {
                        logger.error(`called updateMaster: master(id:${documentContent.instanceId}, ip: ${documentContent.ip}) not updated.`); // eslint-disable-line max-len
                        return false;
                    }
                } catch (error) {
                    logger.error(`updateMaster > error: ${error}`);
                    return false;
                }
            }

            async addInstanceToMonitor(instance, nextHeartBeatTime) {
                logger.info('calling addInstanceToMonitor');
                let documentContent = {
                    ip: instance.getPrimaryPrivateIp(),
                    instanceId: instance.instanceId,
                    vmId: instance.properties.vmId,
                    scaleSetName: process.env.SCALESET_NAME,
                    nextHeartBeatTime: nextHeartBeatTime,
                    heartBeatLostCount: 0
                };

                let documentId = instance.properties.vmId,
                    replaced = true;
                try {
                    let doc = await azureApiCosmosDBCreateDocument(process.env.SCALESET_DB_ACCOUNT,
                        databaseName, dbCollectionMonitored, documentId, documentContent, replaced,
                        masterKey);
                    if (doc) {
                        logger.info(`called addInstanceToMonitor: ${documentId} monitored.`);
                        return true;
                    } else {
                        logger.error(`called addInstanceToMonitor: ${documentId} not monitored.`);
                        return false;
                    }
                } catch (error) {
                    logger.error(`addInstanceToMonitor > error: ${error}`);
                    return false;
                }
            }

            async listMonitoredInstances() {
                const queryObject = {
                    query: `SELECT * FROM ${dbCollectionMonitored} c WHERE c.scaleSetName = @scaleSetName`, // eslint-disable-line max-len
                    parameters: [
                        {
                            name: '@scaleSetName',
                            value: `${process.env.SCALESET_NAME}`
                        }
                    ]
                };

                try {
                    let instances = {},
                        docs = await azureApiCosmosDbQuery(
                            process.env.SCALESET_DB_ACCOUNT, {
                                dbName: databaseName,
                                collectionName: dbCollectionMonitored,
                                partitioned: true,
                                queryObject: queryObject
                            }, masterKey);
                    if (Array.isArray(docs)) {
                        docs.forEach(doc => {
                            instances[doc.instanceId] = doc;
                        });
                    }
                    return instances;
                } catch (error) {
                    logger.error(error);
                }
                return null;
            }

            getCallingInstanceId(_request) {
                try {
                    //try to get instance id from headers
                    if(_request && _request.headers && _request.headers['fos-instance-id']){
                        return _request.headers['fos-instance-id'];
                    }
                    else{
                        //try to get instance id from body
                        if(_request && _request.body && _request.body.instance){
                            return _request.body.instance;
                        } else return null;
                    }
                } catch (error) {
                    return error ? null : null;
                }
            }

            getHeartBeatInterval(_request) {
                try {
                    if(_request && _request.body && _request.body.interval){
                        return parseInt(_request.body.interval);
                    } else return null;
                } catch (error) {
                    return error ? null : null;
                }
            }

            async getMasterInfo() {
                const queryObject = {
                    query: `SELECT * FROM ${dbCollectionMaster} c WHERE c.id = @id`,
                    parameters: [
                        {
                            name: '@id',
                            value: `${process.env.SCALESET_NAME}-master`
                        }
                    ]
                };

                try {
                    let docs = await azureApiCosmosDbQuery(process.env.SCALESET_DB_ACCOUNT, {
                        dbName: databaseName,
                        collectionName: dbCollectionMaster,
                        partitioned: true,
                        queryObject: queryObject
                    }, masterKey);
                    if (docs.length > 0) {
                        return docs[0];
                    } else {
                        return null;
                    }
                } catch (error) {
                    logger.error(error);
                }
                return null;
            }

            async AcquireMutex(collectionName) {
                let _electionLock = null,
                    _purge = false,
                    _now = Math.floor(Date.now() / 1000);
                let _getMutex = async function() {
                    const queryObject = {
                        query: `SELECT * FROM ${dbCollectionMutex} c WHERE c.collectionName = @collectionName`, // eslint-disable-line max-len
                        parameters: [
                            {
                                name: '@collectionName',
                                value: `${collectionName}`
                            }
                        ]
                    };

                    try {
                        let docs = await azureApiCosmosDbQuery(process.env.SCALESET_DB_ACCOUNT, {
                            dbName: databaseName,
                            collectionName: dbCollectionMutex,
                            partitioned: true,
                            queryObject: queryObject
                        }, masterKey);
                        _electionLock = docs[0];
                    } catch (error) {
                        _electionLock = null;
                        logger.error(error);
                    }
                    return _electionLock;
                };

                let _createMutex = async function(purge) {
                    logger.info('calling _createMutex');
                    let documentContent = {
                        servingStatus: 'activated',
                        collectionName: collectionName,
                        acquireLocalTime: _now
                    };

                    let documentId =
                        uuidGenerator(JSON.stringify(documentContent) + ___request_uuid),
                        replaced = false;
                    try {
                        if (purge && _electionLock) {
                            await azureApiCosmosDBDeleteDocument(process.env.SCALESET_DB_ACCOUNT,
                                databaseName, dbCollectionMutex, _electionLock.id, masterKey);
                        }
                        let doc = await azureApiCosmosDBCreateDocument(
                            process.env.SCALESET_DB_ACCOUNT, databaseName,
                            dbCollectionMutex, documentId, documentContent, replaced,
                            masterKey);
                        if (doc) {
                            _electionLock = doc;
                            logger.info(`called _createMutex: mutex(${collectionName}) created.`);
                            return true;
                        } else {
                            logger.warn(`called _createMutex: mutex(${collectionName}) not created.`); // eslint-disable-line max-len
                            return true;
                        }
                    } catch (error) {
                        logger.error(`_createMutex > error: ${error}`);
                        return false;
                    }
                };

                await _getMutex();
                // mutex should last no more than 5 minute (Azure function default timeout)
                if (_electionLock && _now - _electionLock.acquireLocalTime > 300) {
                    // purge the dead mutex
                    _purge = true;
                }
                // no mutex?
                if (!_electionLock || _purge) {
                    // create one
                    let created = await _createMutex(_purge);
                    if (!created) {
                        throw new Error(`Error in acquiring mutex(${collectionName})`);
                    }
                    return _electionLock;
                } else {
                    return null;
                }
            }

            async releaseMutex(collectionName, mutex) {
                logger.info(`calling releaseMutex: mutex(${collectionName}, ${mutex.id}).`);
                let documentId = mutex.id;
                try {
                    let deleted =
                        await azureApiCosmosDBDeleteDocument(
                            process.env.SCALESET_DB_ACCOUNT, databaseName, dbCollectionMutex,
                            documentId, masterKey);
                    if (deleted) {
                        logger.info(`called releaseMutex: mutex(${collectionName}) released.`);
                        return true;
                    } else {
                        logger.warn(`called releaseMutex: mutex(${collectionName}) not found.`);
                        return true;
                    }
                } catch (error) {
                    logger.info(`releaseMutex > error: ${error}`);
                    return false;
                }
            }

            /**
             *
             * @param {Ojbect} instance the instance to update. minimum required
             *      properties {vmId: <string>}
             */
            async updateInstanceToMonitor(instance) { // eslint-disable-line no-unused-vars
                // TODO: will not implement instance updating in V3
                // always return true
                return await Promise.resolve(true);
            }

            /**
             * handle instance removal
             * @param {Object} instance the instance to remove. minimum required
             *      properties{vmId: <string>}
             */
            async removeInstance(instance) { // eslint-disable-line no-unused-vars
                // TODO: will not implement instance removal in V3
                // always return true
                return await Promise.resolve(true);
            }
        };
    }

    function getLifecycleItem() {
        /**
         * Contains all the relevant information needed to complete lifecycle actions for a given
         * fortigate instance, as well as info needed to clean up the related database entry.
         */
        return class LifecycleItem {
            /**
             * @param {String} instanceId Id of the fortigate instance.
             * @param {Object} detail Opaque information used by the platform to manage this item.
             * @param {Date} [timestamp=Date.now()] Optional timestamp for this record.
             */
            constructor(instanceId, detail, timestamp = null) {
                this.instanceId = instanceId;
                this.timestamp = timestamp || Date.now();
                this.detail = detail;
            }

            /**
             * Return a POJO DB entry with capitalized properties.. (not sure why)
             * @returns {Object} object {FortigateInstance, Timestamp, Detail}
             */
            toDb() {
                return {
                    FortigateInstance: this.instanceId,
                    Timestamp: this.timestamp,
                    Detail: this.detail
                };

            }

            /**
             * Resucitate from a stored DB entry
             * @param {Object} entry Entry from DB
             * @returns {LifecycleItem} A new lifecycle item.
             */
            static fromDb(entry) {
                return new LifecycleItem(entry.FortigateInstance, entry.Detail, entry.Timestamp);
            }
        };
    }

    function getAutoscaleHandler() {

        const
            AUTOSCALE_SECTION_EXPR =
            /(?:^|\n)\s*config?\s*system?\s*auto-scale[\s\n]*((?:.|\n)*)\bend\b/,
            SET_SECRET_EXPR = /(set\s+(?:psksecret|password)\s+).*/g;

        /**
         * AutoscaleHandler contains the core used to handle serving configuration files and
         * manage the autoscale events from multiple cloud platforms.
         *
         * Use this class in various serverless cloud contexts. For each serverless cloud
         * implementation extend this class and implement the handle() method. The handle() method
         * should call other methods as needed based on the input events from that cloud's
         * autoscale mechanism and api gateway requests from the fortigate's callback-urls.
         * (see reference AWS implementation {@link AwsAutoscaleHandler})
         *
         * Each cloud implementation should also implement a concrete version of the abstract
         * {@link CloudPlatform} class which should be passed to super() in the constructor. The
         * CloudPlatform interface should abstract each specific cloud's api. The reference
         * implementation {@link AwsPlatform} handles access to the dynamodb for persistence and
         * locking, interacting with the aws autoscaling api and determining the api endpoint url
         * needed for the fortigate config's callback-url parameter.
         */
        class AutoscaleHandler {

            constructor(platform, baseConfig) {
                this.platform = platform;
                this._baseConfig = baseConfig;
            }

            throwNotImplementedException() {
                throw new Error('Not Implemented');
            }

            async handle() {
                await this.throwNotImplementedException();
            }

            async init() {
                await this.platform.init();
            }

            async getConfig(ip) {
                this.step = 'handler:getConfig:holdElection';
                const
                    masterIp = await this.holdMasterElection(ip);
                if (masterIp === ip) {

                    this.step = 'handler:getConfig:completeMaster';
                    await this.completeMasterInstance(await this.platform.findInstanceIdByIp(ip));

                    this.step = 'handler:getConfig:getMasterConfig';
                    return await this.getMasterConfig(await this.platform.getCallbackEndpointUrl());
                } else {

                    this.step = 'handler:getConfig:getSlaveConfig';
                    return await this.getSlaveConfig(masterIp,
                        await this.platform.getCallbackEndpointUrl());
                }
            }

            async getMasterConfig(callbackUrl) {
                return await this._baseConfig.replace(/\$\{CALLBACK_URL}/, callbackUrl);
            }

            async getSlaveConfig(masterIp, callbackUrl) {
                const
                    autoScaleSectionMatch = AUTOSCALE_SECTION_EXPR
                    .exec(await this._baseConfig),
                    autoScaleSection = autoScaleSectionMatch && autoScaleSectionMatch[1],
                    matches = [
                        /set\s+sync-interface\s+(.+)/.exec(autoScaleSection),
                        /set\s+psksecret\s+(.+)/.exec(autoScaleSection)
                    ];
                const [syncInterface, pskSecret] = matches.map(m => m && m[1]),
                    apiEndpoint = callbackUrl,
                    config = `
                        diag sys ha hadiff log enable
                        diag debug app hasync -1
                        diag debug enable
                        config system auto-scale
                            set status enable
                            set sync-interface ${syncInterface}
                            set role slave
                            set master-ip ${masterIp}
                            set callback-url ${apiEndpoint}
                            set psksecret ${pskSecret}
                        end
                        config system dns
                            unset primary
                            unset secondary
                        end
                        config system global
                            set admin-console-timeout 300
                        end
                        config system global
                            set admin-sport 8443
                        end
                    `;
                if (!syncInterface || !pskSecret) {
                    throw new Error(`Base config is invalid: ${
                        JSON.stringify({
                            syncInterface,
                            apiEndpoint,
                            masterIp,
                            pskSecret: pskSecret && typeof pskSecret
                        })}`);
                }
                if (!apiEndpoint) {
                    throw new Error('Api endpoint is missing');
                }
                if (!masterIp) {
                    throw new Error('Master ip is missing');
                }
                config.replace(SET_SECRET_EXPR, '$1 *');
                return config;
            }

            async holdMasterElection(ip) {
                let masterIp;
                try {
                    masterIp = await this.platform.getElectedMaster();
                } catch (ex) {
                    console.log(ex.message);
                }
                const masterInstanceId =
                    masterIp && await this.platform.findInstanceIdByIp(masterIp);
                if (!masterInstanceId || !masterIp) {
                    console.log(!masterIp ?
                        'no master, maybe I will be the new master?' :
                        'master is dead, long live the master');
                    await this.platform.putMasterElectionVote(ip, masterIp);
                    masterIp = await this.platform.getElectedMaster();
                }
                console.log(ip === masterIp ? `Election won! new master is ${masterIp}` :
                    `${ip} lost the election, master is ${masterIp}`);
                return masterIp;
            }

            async completeLifecycleAction(instanceId, success = true) {
                const
                    item = await this.platform.getPendingLifecycleAction(instanceId),
                    data = await this.platform.completeLifecycleAction(item, success);

                await this.platform.cleanUpDb(item);
                return {
                    item,
                    data
                };
            }

            async completeMasterInstance(instanceId) {
                const {
                    item,
                    result
                } = await this.completeLifecycleAction(instanceId, true);
                let instanceProtected = false;
                try {
                    instanceProtected = await this.platform.protectInstanceFromScaleIn(item);
                } catch (ex) {
                    console.error('Unable to protect instance from scale in:');
                    console.error(ex);
                }
                console.log(`Lifecycle for master ${instanceId} has been completed. ` +
                    `Protected: ${instanceProtected}`);
                return result;
            }

            responseToHeartBeat(masterIp) {
                let response = {};
                if (masterIp) {
                    response['master-ip'] = masterIp;
                }
                return JSON.stringify(response);
            }
        }

        return AutoscaleHandler;
    }

    function getAzurePlatform(CloudPlatform, LifecycleItem) { // eslint-disable-line no-unused-vars
        const
            armClient = getAzureArmClient();
        return class AzurePlatform extends CloudPlatform {
            async init() {
                let _initDB = async function() {
                    return await azureApiCosmosDBCreateDB(process.env.SCALESET_DB_ACCOUNT,
                            databaseName, masterKey)
                        .then(status => {
                            if (status === true) {
                                return Promise.all([
                                    // create instances
                                    azureApiCosmosDBCreateCollection(
                                        process.env.SCALESET_DB_ACCOUNT, databaseName,
                                        dbCollectionMonitored, masterKey),
                                    azureApiCosmosDBCreateCollection(
                                        process.env.SCALESET_DB_ACCOUNT, databaseName,
                                        dbCollectionMaster, masterKey),
                                    azureApiCosmosDBCreateCollection(
                                        process.env.SCALESET_DB_ACCOUNT, databaseName,
                                        dbCollectionMutex, masterKey)
                                ]);
                            } else {
                                logger.info('DB exists. Skip creating collections.');
                                return true;
                            }
                        });
                };

                await Promise.all([
                    _initDB(),
                    await armClient.authWithServicePrincipal(process.env.REST_APP_ID,
                        process.env.REST_APP_SECRET, process.env.TENANT_ID)]);
                armClient.useSubscription(process.env.SUBSCRIPTION_ID);
            }

            async getCallbackEndpointUrl(fromContext = null) {
                return await fromContext ? fromContext.originalUrl : null;
            }

            async findInstanceIdById(vmId) {
                let parameters = {
                    resourceGroup: process.env.RESOURCE_GROUP,
                    scaleSetName: process.env.SCALESET_NAME
                };
                let virtualMachines = await this.listAllInstances(parameters);
                for (let virtualMachine of virtualMachines) {
                    if (virtualMachine.properties.vmId === vmId) {
                        return virtualMachine;
                    }
                }
                return null;
            }

            async protectInstanceFromScaleIn(item, protect = true) {
                return await Promise.reject(false && protect);
            }

            async listAllInstances(parameters) {
                logger.info('calling listAllInstances');
                let virtualMachines =
                    await armClient.ComputeClient.VirtualMachineScaleSets.listVirtualMachines(
                        parameters.resourceGroup, parameters.scaleSetName);
                logger.info('called listAllInstances');
                return virtualMachines;
            }

            async describeInstance(parameters) {
                logger.info('calling describeInstance');
                let virtualMachine =
                    await armClient.ComputeClient.VirtualMachineScaleSets.getVirtualMachine(
                        parameters.resourceGroup, parameters.scaleSetName,
                        parameters.virtualMachineId);
                logger.info('called describeInstance');

                return (function(vm) {
                    vm.getPrimaryPrivateIp = () => {
                        /* eslint-disable max-len */
                        for (let networkInterface of vm.properties.networkProfile.networkInterfaces) {
                            if (networkInterface.properties.primary) {
                                for (let ipConfiguration of networkInterface.properties.ipConfigurations) {
                                    if (ipConfiguration.properties.primary) {
                                        return ipConfiguration.properties.privateIPAddress;
                                    }
                                }
                            }
                        }
                        return null;
                        /* eslint-enable max-len */
                    };
                    return vm;
                })(virtualMachine);
            }

            /**
             * get the health check info about an instance been monitored.
             * @param {Object} instance instance object which a vmId property is required.
             * @param {Number} heartBeatInterval integer value, unit is second.
             */
            async getInstanceHealthCheck(instance, heartBeatInterval) {
                // TODO: not fully implemented in V3
                if (!(instance && instance.vmId)) {
                    logger.error(`getInstanceHealthCheck > error: no vmId property found on instance: ${JSON.stringify(instance)}`); // eslint-disable-line max-len
                    return Promise.reject(`invalid instance: ${JSON.stringify(instance)}`);
                }
                const queryObject = {
                    query: `SELECT * FROM ${dbCollectionMonitored} c WHERE c.scaleSetName = @scaleSetName AND c.vmId = @vmId`, // eslint-disable-line max-len
                    parameters: [
                        {
                            name: '@scaleSetName',
                            value: `${process.env.SCALESET_NAME}`
                        },
                        {
                            name: '@vmId',
                            value: `${instance.vmId}`
                        }
                    ]
                };

                try {
                    let docs = await azureApiCosmosDbQuery(process.env.SCALESET_DB_ACCOUNT, {
                        dbName: databaseName,
                        collectionName: dbCollectionMonitored,
                        partitioned: true,
                        queryObject: queryObject
                    }, masterKey);
                    if (Array.isArray(docs) && docs.length > 0) {
                        // always return healthy state (v3 implementation)
                        logger.info('called getInstanceHealthCheck');
                        return {
                            healthy: !!heartBeatInterval, // TODO: need to implement logic here
                            heartBeatLostCount: docs[0].heartBeatLostCount,
                            nextHeartBeatTime: docs[0].nextHeartBeatTime
                        };
                    } else {
                        logger.info('called getInstanceHealthCheck: no record found');
                        return null;
                    }
                } catch (error) {
                    logger.error(error);
                    logger.info('called getInstanceHealthCheck with error.');
                    return null;
                }
            }
        };
    }

    function getAzurePlatformLogger() {
        return class AzureLogger extends Logger {
            constructor(loggerObject) {
                super(loggerObject);
            }
            setLoggingLevel(levelObject) {
                if (levelObject) {
                    this.level = levelObject;
                }
            }
            log(object) {
                if (!(this.level && this.level.log === false)) {
                    this.logger(object);
                }
            }
            info(object) {
                if (!(this.level && this.level.info === false)) {
                    this.logger.info(object);
                }
            }
            warn(object) {
                if (!(this.level && this.level.warn === false)) {
                    this.logger.warn(object);
                }
            }
            error(object) {
                if (!(this.level && this.level.error === false)) {
                    this.logger.error(object);
                }
            }
        };
    }
}
