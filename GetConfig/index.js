'use strict';

const request = require('request');
const crypto = require('crypto');
const uuidv5 = require('uuid/v5');
const MsRest = require('ms-rest-azure');

/**
 * Global req for test use, must delete
 */

/**
 * Debug use
 */

//TODO: where to store this master key?
let ___request_uuid;
const masterKey = process.env.REST_API_MASTER_KEY;
const scaleSetName = process.env.SCALESET_NAME;
const databaseName = `fortigateInstances`;
const dbCollectionMonitored = `instances`;
const dbCollectionMaster = `masterPool`;
const dbCollectionMutex = `mutex`;
/**
 * Here are a few global functions to handle Azure RESTful API
 */

const uuidGenerator = function(inStr) {
    return uuidv5(inStr, uuidv5.URL);
};

function sleep(ms){
    return new Promise(resolve=>{
        logger.warn(`sleep for ${ms} ms`);
        setTimeout(resolve,ms);
    })
}

var ___context, logger;

/**
 * 
 */
function getAzureArmClient() {
    var _credentials, _token, _subscription;
    /**
     * will throw error if there is any.
     * @param {*} url 
     */
    async function AzureArmGet(url) {
        return new Promise((resolve, reject) => {
            logger.info(`calling AzureArmGet url: ${url}`);
            request.get({
                url: url,
                headers: {
                    'Authorization': `Bearer ${_token}`
                }
            }, function(error, response, body) {
                //TODO: handle error.
                if (error) {
                    logger.error(`called AzureArmGet but returned unknown error ${JSON.stringify(error)}`);
                    reject(error);
                } else {
                    if (response.statusCode == 200) {
                        resolve(body);
                    } else {
                        logger.error(`called AzureArmGet but returned error (code: ${response.statusCode}) ${response.body}`);
                        reject(response);
                    }
                }
            });
        });
    }

    /**
     * this function doesn't do error handling. The caller must do error handling.
     * @param {*} resourceId 
     * @param {*} apiVersion 
     */
    async function getResource(resourceId, apiVersion) {
        const url = `https://management.azure.com${resourceId}?api-version=${apiVersion}`;
        let response = await AzureArmGet(url);
        return JSON.parse(response);
    }

    async function getNetworkInterface(resourceId) {
        try {
            logger.info(`calling getNetworkInterface.`);
            let response = await getResource(resourceId, '2017-12-01');
            let body = JSON.parse(response.body);
            logger.info(`called getNetworkInterface.`);
            return body;
        } catch (error) {
            logger.error(`getNetworkInterface > error ${JSON.stringify(error)}`);
        }
        return null;
    };

    async function getVirtualMachineScaleSets(resourceGroup) {
        let resourceId = `/subscriptions/${_subscription}/resourceGroups/${resourceGroup}/providers/Microsoft.Compute/virtualMachineScaleSets`;
        try {
            logger.info(`calling getVirtualMachineScaleSets.`);
            let response = await getResource(resourceId, '2017-12-01');
            logger.info(`called getVirtualMachineScaleSets. ${JSON.stringify(response)}`);
            return response.value;
        } catch (error) {
            logger.error(`getVirtualMachineScaleSets > error ${JSON.stringify(error)}`);
            return [];
        }
    };

    async function listVirtualMachines(resourceGroup, scaleSetName) {
        let resourceId = `/subscriptions/${_subscription}/resourceGroups/${resourceGroup}/providers/Microsoft.Compute/virtualMachineScaleSets/${scaleSetName}/virtualMachines`;
        try {
            logger.info(`calling listVirtualMachines.`);
            let response = await getResource(resourceId, '2017-12-01');
            logger.info(`called listVirtualMachines.`);
            return response.value;
        } catch (error) {
            logger.error(`listVirtualMachines > error ${JSON.stringify(error)}`);
            return [];
        }
    };

    /**
     * Get a virtual machine, including its network interface details
     * @param {String} resourceGroup 
     * @param {String} scaleSetName 
     * @param {String} virtualMachineId 
     */
    async function getVirtualMachine(resourceGroup, scaleSetName, virtualMachineId) {
        let resourceId = `/subscriptions/${_subscription}/resourceGroups/${resourceGroup}/providers/Microsoft.Compute/virtualMachineScaleSets/${scaleSetName}/virtualMachines/${virtualMachineId}`;
        try{
            let virtualMachine = await getResource(resourceId, '2017-12-01');
            let networkInterfaces = await getResource(resourceId+'/networkInterfaces', '2017-12-01');
            virtualMachine.properties.networkProfile.networkInterfaces = networkInterfaces.value;
            return virtualMachine;
        }catch(error){

        }
    }

    /**
     * find the first virtual machine in the scale set.
     * 
     * @param {*} resourceGroup 
     * @param {*} scaleSetName 
     */
    async function getFirstVirtualMachine(resourceGroup) {
        logger.info(`calling getFirstVirtualMachine.`);
        let found = {};
        let scaleSet = await getVirtualMachineScaleSets(resourceGroup);
        if (scaleSet.length == 0) {
            logger.info(`getFirstVirtualMachine > error: no scale set found.`);
        } else {
            let scaleSetName = scaleSet[0].name;
            let virtualMachines = await listVirtualMachines(resourceGroup, scaleSetName);
            for (let vm of virtualMachines) {
                let resourceId = vm.properties.networkProfile.networkInterfaces[0].id;
                try {
                    let nic = await getResource(resourceId, '2017-12-01');
                    let vmIp = nic.properties.ipConfigurations[0].properties.privateIPAddress;
                    if (vmIp) {
                        found = {
                            virtualMachine: vm,
                            networkInterface: nic
                        };
                        break;
                    }
                } catch (error) {
                    logger.warn(`getFirstVirtualMachine > error querying for networkInterface: ${JSON.stringify(error)}`);
                }
            }
        }
        logger.info(`called getFirstVirtualMachine.`);
        return found;
    }

    /**
     * This lookup takes longer time to complete. a few round of http requests require. 
     * can we optimize to reduce this ?
     * @param {*} resourceGroup 
     * @param {*} scaleSetName 
     * @param {*} ip 
     */
    async function getVirtualMachineByIp(resourceGroup, scaleSetName, ip) {
        logger.info(`calling getFirstVirtualMachine.`);
        let found = {},
            virtualMachines = await listVirtualMachines(resourceGroup, scaleSetName);
        for (let vm of virtualMachines.value) {
            try {
                let nic = await getResource(resourceId, '2017-12-01');
                let vmIp = nic.properties.ipConfigurations[0].properties.privateIPAddress;
                if (ip === vmIp) {
                    found = {
                        virtualMachine: vm,
                        networkInterface: nic
                    };
                    break;
                }
            } catch (error) {
                logger.warn(`getFirstVirtualMachine > error querying for networkInterface: ${JSON.stringify(error)}`);
            }
        }
        logger.info(`called getFirstVirtualMachine.`);
        return found;
    };

    async function authWithServicePrincipal(client_id, client_secret, tenant_id){
        return new Promise(function(resolve, reject) {
            logger.info(`calling authWithServicePrincipal.`);
            MsRest.loginWithServicePrincipalSecret(client_id, client_secret, tenant_id, (error, credentials) => {
                if (error) {
                    logger.error(`authWithServicePrincipal > error: ${JSON.stringify(error)}`);
                    reject(error);
                }
                _credentials = credentials.tokenCache._entries[0];
                _token = _credentials.accessToken;
                logger.info(`called authWithServicePrincipal.`);
                resolve(true);
            });
        });
    };

    return {
        authWithServicePrincipal: authWithServicePrincipal,
        useSubscription: function(subscription) {
            _subscription = subscription;
        },
        ComputeClient: {
            VirtualMachineScaleSets: {
                getNetworkInterface: getNetworkInterface,
                getVirtualMachineByIp: getVirtualMachineByIp,
                getFirstVirtualMachine: getFirstVirtualMachine,
                listVirtualMachines: listVirtualMachines,
                getVirtualMachine: getVirtualMachine
            }
        }
    };
};

function getAuthorizationTokenUsingMasterKey(verb, resourceType, resourceId, date, masterKey) {
    var key = new Buffer(masterKey, "base64");

    var text = (verb || "").toLowerCase() + "\n" +
        (resourceType || "").toLowerCase() + "\n" +
        (resourceId || "") + "\n" +
        date.toLowerCase() + "\n" +
        "" + "\n";

    var body = new Buffer(text, "utf8");
    var signature = crypto.createHmac("sha256", key).update(body).digest("base64");

    var MasterToken = "master";

    var TokenVersion = "1.0";

    return encodeURIComponent("type=" + MasterToken + "&ver=" + TokenVersion + "&sig=" + signature);
}

async function azureApiCosmosDBCreateDB(dbAccount, dbName, masterKey) {
    return new Promise(function(resolve, reject) {
        logger.info(`calling azureApiCosmosDBCreateDB.`);
        let date = (new Date()).toUTCString();
        let token = getAuthorizationTokenUsingMasterKey('post', 'dbs', '', date, masterKey);
        let path = `https://${dbAccount}.documents.azure.com/dbs`;
        let headers = {
            'Authorization': token,
            'x-ms-version': '2017-02-22',
            'x-ms-date': date,
        };
        request.post({
            url: path,
            headers: headers,
            body: {
                id: dbName
            },
            json: true
        }, function(error, response, body) {
            if (error) {
                logger.error(`called azureApiCosmosDBCreateDB > unknown error: ${JSON.stringify(response)}`);
                reject(error);
            } else if (response.statusCode === 201) {
                logger.info(`called azureApiCosmosDBCreateDB: ${dbName} created.`);
                resolve(true);
            } else if (response.statusCode === 409) {
                logger.warn(`called azureApiCosmosDBCreateDB: not created, ${dbName} already exists.`);
                resolve(false); //db exists.
            } else {
                logger.error(`called azureApiCosmosDBCreateDB > other error: ${JSON.stringify(response)}`);
                reject(response);
            }
        });
    });
}

async function azureApiCosmosDBCreateCollection(dbAccount, dbName, collectionName, masterKey) {
    return new Promise(function(resolve, reject) {
        logger.info(`calling azureApiCosmosDBCreateCollection.`);
        let date = (new Date()).toUTCString();
        let token = getAuthorizationTokenUsingMasterKey('post', 'colls', `dbs/${dbName}`, date, masterKey);
        let path = `https://${dbAccount}.documents.azure.com/dbs/${dbName}/colls`;
        let headers = {
            'Authorization': token,
            'x-ms-version': '2017-02-22',
            'x-ms-date': date,
        };
        request.post({
            url: path,
            headers: headers,
            body: {
                id: collectionName
            },
            json: true
        }, function(error, response, body) {
            if (error) {
                logger.error(`called azureApiCosmosDBCreateCollection > unknown error: ${JSON.stringify(response)}`);
                reject(error);
            } else if (response.statusCode === 201) {
                logger.info(`called azureApiCosmosDBCreateCollection: ${dbName}/${collectionName} created.`);
                resolve(true);
            } else if (response.statusCode === 409) {
                logger.warn(`called azureApiCosmosDBCreateCollection: not created, ${dbName}/${collectionName} already exists.`);
                resolve(false); //db exists.
            } else {
                logger.error(`called azureApiCosmosDBCreateCollection > other error: ${JSON.stringify(response)}`);
                reject(response);
            }
        });
    });
}

async function azureApiCosmosDBCreateDocument(dbAccount, dbName, collectionName, documentId, documentContent, replaced, masterKey) {
    return new Promise(function(resolve, reject) {
        logger.info(`calling azureApiCosmosDBCreateDocument.`);
        if (!(dbName && collectionName && documentId)) {
            //TODO: what should be returned from here?
            reject(null);
        }
        let date = (new Date()).toUTCString();
        let token = getAuthorizationTokenUsingMasterKey('post', 'docs', `dbs/${dbName}/colls/${collectionName}`, date, masterKey);
        let path = `https://${dbAccount}.documents.azure.com/dbs/${dbName}/colls/${collectionName}/docs`;
        let headers = {
            'Authorization': token,
            'x-ms-version': '2017-02-22',
            'x-ms-date': date,
        };
        if (replaced) {
            headers['x-ms-documentdb-is-upsert'] = true;
        }
        let content = documentContent || {};
        content['id'] = documentId;
        try {
            JSON.stringify(content);
        } catch (error) {
            //TODO: what should be returned from here?
            reject(null);
        }
        request.post({
            url: path,
            headers: headers,
            body: content,
            json: true
        }, function(error, response, body) {
            if (error) {
                logger.error(`called azureApiCosmosDBCreateDocument > unknown error: ${JSON.stringify(response)}`);
                reject(error);
            } else if (response.statusCode === 200) {
                logger.info(`called azureApiCosmosDBCreateDocument: ${dbName}/${collectionName}/${documentId} not modified.`);
                resolve(body);
            } else if (response.statusCode === 201) {
                logger.info(`called azureApiCosmosDBCreateDocument: ${dbName}/${collectionName}/${documentId} created.`);
                resolve(body);
            } else if (response.statusCode === 409) {
                logger.warn(`called azureApiCosmosDBCreateDocument: not created, ${dbName}/${collectionName}/${documentId} already exists.`);
                resolve(null); //document with such id exists.
            } else {
                logger.error(`called azureApiCosmosDBCreateDocument > other error: ${JSON.stringify(response)}`);
                reject(response);
            }
        });
    });
}

async function azureApiCosmosDBDeleteDocument(dbAccount, dbName, collectionName, documentId, masterKey) {
    return new Promise(function(resolve, reject) {
        logger.info(`calling azureApiCosmosDBDeleteDocument.`);
        if (!(dbName && collectionName && documentId)) {
            //TODO: what should be returned from here?
            reject(null);
        }
        let date = (new Date()).toUTCString();
        let token = getAuthorizationTokenUsingMasterKey('delete', 'docs', `dbs/${dbName}/colls/${collectionName}/docs/${documentId}`, date, masterKey);
        let path = `https://${dbAccount}.documents.azure.com/dbs/${dbName}/colls/${collectionName}/docs/${documentId}`;
        let headers = {
            'Authorization': token,
            'x-ms-version': '2017-02-22',
            'x-ms-date': date,
        };
        request.delete({
            url: path,
            headers: headers
        }, function(error, response, body) {
            if (error) {
                logger.error(`called azureApiCosmosDBDeleteDocument > unknown error: ${JSON.stringify(response)}`);
                reject(error);
            } else if (response.statusCode === 204) {
                logger.info(`called azureApiCosmosDBDeleteDocument: ${dbName}/${collectionName}/${documentId} deleted.`);
                resolve(true);
            } else if (response.statusCode === 404) {
                logger.warn(`called azureApiCosmosDBDeleteDocument: not deleted, ${dbName}/${collectionName}/${documentId} not found.`);
                resolve(false); //document with such id exists.
            } else {
                logger.error(`called azureApiCosmosDBDeleteDocument > other error: ${JSON.stringify(response)}`);
                reject(response);
            }
        });
    });
}

/**
 * 
 * @param {*} dbAccount DB account
 * @param {*} resource  object {dbName, collectionName, queryObject}
 * @param {*} masterKey 
 */
async function azureApiCosmosDbQuery(dbAccount, resource, masterKey) {
    return new Promise((resolve, reject) => {
        logger.info(`calling azureApiCosmosDbQuery.`);
        let date = (new Date()).toUTCString();
        let resourcePath = '',
            resourceType = '';
        if (resource.dbName !== undefined) {
            resourceType = 'dbs';
            resourcePath += `dbs/${resource.dbName}`;
        }
        if (resource.collectionName != undefined) {
            if (resource.dbName === undefined) {
                //TODO: what should return by this reject?
                logger.error(`called azureApiCosmosDbQuery: invalid resource ${JSON.stringify(resource)}`);
                reject({});
                return;
            }
            resourceType = 'colls';
            resourcePath += `/colls/${resource.collectionName}`;
        }
        resourceType = 'docs';
        // resourcePath += `/docs`;

        let token = getAuthorizationTokenUsingMasterKey('post', resourceType, resourcePath, date, masterKey);
        let path = `https://${dbAccount}.documents.azure.com/${resourcePath}/docs`;
        let headers = {
            'Authorization': token,
            'x-ms-version': '2017-02-22',
            'x-ms-date': date,
            'x-ms-documentdb-isquery': "True",
            'Content-Type': 'application/query+json'
        };
        if (resource.partitioned) {
            headers['x-ms-documentdb-query-enablecrosspartition'] = true;
            if (resource.partitionkey) {
                headers['x-ms-documentdb-partitionkey'] = resource.partitionkey;
            }
        }
        let body = "";
        try {
            body = JSON.stringify({
                query: resource.queryObject.query,
                parameters: resource.queryObject.parameters || []
            });
        } catch (error) {
            //TODO: what should return by this reject?
            logger.error(`called azureApiCosmosDbQuery: invalid queryObject -> ${JSON.stringify(resource.queryObject)}.`);
            reject({});
        }
        request.post({
            url: path,
            headers: headers,
            body: body
        }, function(error, response, body) {
            if (error) {
                logger.error(`called azureApiCosmosDbQuery > unknown error: ${JSON.stringify(response)}`);
                reject(error);
            } else if (response.statusCode === 200) {
                logger.info(`azureApiCosmosDbQuery: ${resourcePath} retrieved.`);
                try {
                    let res = JSON.parse(response.body);
                    logger.info(`called azureApiCosmosDbQuery.`);
                    resolve(res.Documents);
                } catch (error) {
                    logger.warn(`called azureApiCosmosDbQuery: Documents object parsed failed.`);
                    //TODO: what should return if failed to parse the documents?
                    reject({});
                }
            } else if (response.statusCode === 304) {
                logger.warn(`called azureApiCosmosDbQuery: ${resourcePath} not modified. return empty response body.`);
                reject(response);
            } else if (response.statusCode === 404) {
                logger.warn(`called azureApiCosmosDbQuery: not found, ${resourcePath} was deleted.`);
                reject(response);
            } else {
                logger.error(`called azureApiCosmosDbQuery > other error: ${JSON.stringify(response)}`);
                reject(response);
            }
        });
    });
}


module.exports = async function(context, req) {
    ___context = context;
    logger = ___context.log;
    ___request_uuid = uuidGenerator(JSON.stringify(req));
    await new(initModules().AzureAutoscaleHander)().handle(context, req);
};

/**
 * Emulate a module system so we can split this into multiple files later.
 * @TODO: separate into actual separate module files.
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
    return modules;

    function getCloudPlatform() {
        const notImplemented = () => new Error('Not Implemented');
        /**
         * @abstract
         * Class used to define the capabilities required from cloud platform.
         */
        return class CloudPlatform {
            /* eslint-disable no-unused-vars */
            /**
             * Initialize (and wait for) any required resources such as database tables etc.
             */
            async init() {}

            /**
             * Submit an election vote for this ip address to become the master.
             * @param {String} ip Ip of the fortigate which wants to become the master
             * @param {String} purgeMasterIp Ip of the dead master we should purge before voting
             */
            async putMasterElectionVote(ip, purgeMasterIp) {
                throw notImplemented()
            }
            /**
             * Get the ip address which won the master election
             * @returns {String} Ip of the fortigate which should be the auto-sync master
             */
            async getElectedMaster() {
                throw notImplemented()
            }
            /**
             * Get an existing lifecyle action from the database.
             * @param {String} instanceId Instance ID of a fortigate.
             * @returns {LifecycleItem} Item used by the platform to complete a
             *  lifecycleAction
             */
            async getPendingLifecycleAction(instanceId) {
                throw notImplemented()
            }
            /**
             * Put a new lifecycle action into the database
             * @param {LifecycleItem} item Item used by the platform to complete
             *  a lifecycleAction.
             */
            async putPendingLifecycleAction(item) {
                throw notImplemented()
            }
            /**
             * Clean up database the current database entry (or any expired entries)
             * @param {LifecycleItem} [item] Item used to complete a lifecycle
             *  action. When provided, only this item will be cleaned up, otherwise scan for expired
             *  items to purge.
             */
            async cleanUpDb(item = null) {
                throw notImplemented()
            }
            /**
             * Get the url for the callback-url portion of the config.
             */
            async getApiGatewayUrl() {
                throw notImplemented()
            }

            /**
             * Lookup the instanceid using an ip address.
             * @param {String} ip Local ip address of an instance.
             */
            async findInstanceIdByIp(ip) {
                throw notImplemented()
            }

            /**
             * Protect an instance from being scaled out.
             * @param {LifecycleItem} item Item that was used by the platform to complete a
             *  lifecycle action
             * @param {boolean} [protect=true] Whether to add or remove or protection the instance.
             */
            async protectInstanceFromScaleIn(item, protect = true) {
                throw notImplemented()
            }

            /**
             * List all instances with given parameters.
             * @param {Object} parameters parameters necessary for listing all instances.
             */
            async listAllInstances(parameters) {
                throw notImplemented()
            }

            /**
             * Describe an instance
             * @param {Object} parameters parameters necessary for describing an instance.
             */
            async describeInstance(parameters) {
                throw notImplemented()
            }

            /**
             * Delete one or more instances from the auto scaling group
             * @param {Object} parameters parameters necessary for instance deletion.
             */
            async deleteInstances(parameters) {
                throw notImplemented()
            }
            /* eslint-enable no-unused-vars */
        };
    }

    function getAzureAutoscaleHandler(AzurePlatform, AutoscaleHandler, LifecycleItem) {
        /**
         * Implementation of the AutoscaleHandler for handling requests into the Azure function
         * serverless implementation.
         */
        return class AzureAutoscaleHandler extends AutoscaleHandler {
            constructor() {
                const baseConfig = process.env.FTGT_BASE_CONFIG.replace(/\\n/g, '\n');
                super(new AzurePlatform(), baseConfig);
                this._mutex = null;
            }

            async handle(context, req) {
                //let x = require(require.resolve(`${process.cwd()}/azure-arm-client`));
                context.log.info(`start to handle autoscale`);
                context.log.info(`incoming request: ${JSON.stringify(req)}`);
                try {
                    await this.init();
                    //handle get config
                    let config = await this.handleGetConfig(req);
                    context.res = {
                        // status: 200, /* Defaults to 200 */
                        headers: {
                            "Content-Type": "text/plain",
                        },
                        body: config
                    };
                    logger.info(config);

                } catch (error) {
                    context.log.error(error);
                }

            }

            /**
             * Platform specific function.
             * @param {*} request 
             */
            async handleGetConfig(request) {
                logger.info(`calling handleGetConfig`);
                //Currently, we can't retrieve enough information from request to identify an instance.
                //But the client-ip in header can distinguish each caller by port(e.g.: 10.0.128.32:46497)
                let callingInstanceId = await this.getCallingInstanceIdentifier(request);
                //We can set a mutex for master election for now.
                
                let masterInfo, electedMaster = false,
                    electionCompleted = false, counter = 0,
                    nextTime = Date.now(),
                    endTime = nextTime + 10000;//unit ms
                while(!electionCompleted && (nextTime < endTime)){
                    //get the current master
                    masterInfo = await this.getMasterInfo();
                    //if master doesn't exist, hold an election for master
                    if(!masterInfo){

                        //start a mutex because we only allow one thread to handle the election
                        this._mutex = await this.AcquireMutex(dbCollectionMaster);
                        if(this._mutex){
                            //handle election
                            logger.info(`This thread is holding an election.`);
                            try{
                                //TODO: when fortigate is capable to identify itself, determine master by comparing its ip and the
                                //elected master ip.
                                electedMaster = await this.holdMasterElection(null);
                                logger.info(`Election completed.`);
                            }
                            catch(error){
                                //TODO: what to do when error?
                                logger.error(`Something went wrong in the election.`);
                                // throw new Error(`Cannot choose a master Fortigate. Please read function logs for more information`);
                            }
                            finally{
                                //release the mutex
                                await this.releaseMutex(dbCollectionMaster, this._mutex);
                                this._mutex = null;
                            }
                            masterInfo = await this.getMasterInfo();
                        }
                        else{
                            logger.info(`Wait for master election (counter: ${++counter}, time:${Date.now()})`);
                        }
                    }
                    nextTime = Date.now();
                    electionCompleted = !!masterInfo;
                    !electionCompleted && await sleep(1000);
                }

                //TODO: this method won't work because it is still not possible for fortigate to identify itself.
                //so comment the next block out for now until the fortigate has such capability.
                //when fortigate is capable to identify itself, determine master by comparing its ip and the
                //elected master ip.
                /*
                //determine if master or slave config should be returned
                //describe the calling instance
                let parameters = {
                    resourceGroup: process.env.RESOURCE_GROUP,
                    scaleSetName: process.env.SCALESET_NAME,
                    virtualMachineId: callingInstanceId
                };
                let self = await this.platform.describeInstance(parameters);
                //save self to monitored instances db
                await this.addInstanceToMonitor(self);

                if(masterInfo.ip == self.getPrimaryPrivateIp()){
                //the next line needs to comment if the previous line is uncommented.
                 */
                if(electedMaster){
                    logger.info(`called handleGetConfig: returning master(ip: ${masterInfo.ip})`);
                    return await this.getMasterConfig();
                }
                else if(masterInfo && masterInfo.ip){
                    logger.info(`called handleGetConfig: returning slave(master ip: ${masterInfo.ip})`);
                    return await this.getSlaveConfig(masterInfo.ip);
                }
                else {
                    return Promise.reject(`Fatal error: Can't elect a master. Read function logs for more detailed information.`);
                }
            };

            async holdMasterElection(ip) {
                //list all election candidates
                let parameters = {
                    resourceGroup: process.env.RESOURCE_GROUP,
                    scaleSetName: process.env.SCALESET_NAME
                };
                let virtualMachine, candidate, candidates = [];
                let [virtualMachines, moniteredInstances] = await Promise.all([
                    this.platform.listAllInstances(parameters),
                    this.listMonitoredInstances()
                ]);
                for(virtualMachine of virtualMachines){
                    //if candidate is not yet monitored, and it is in the healthy state (Succeeded)
                    //put in in the candidate pool
                    if(moniteredInstances[virtualMachine.instanceId] == undefined
                        && virtualMachine.properties.provisioningState === 'Succeeded'){
                        candidates.push(virtualMachine);
                    }
                }
                
                let instanceId = 0, master = null;
                let promiseAllArray = [],
                    candidateMonitored = false,
                    candidateDescribingFunc = async (candidate)=>{
                        let parameters = {
                            resourceGroup: process.env.RESOURCE_GROUP,
                            scaleSetName: process.env.SCALESET_NAME,
                            virtualMachineId: candidate.instanceId
                        };
                        return this.platform.describeInstance(parameters);
                    };
                if(candidates.length > 0){
                    //choose the one with smaller instanceId
                    for(candidate of candidates){
                        if(instanceId == 0 || candidate.instanceId < instanceId){
                            instanceId = candidate.instanceId;
                            master = candidate;
                        }
                        promiseAllArray.push((candidateDescribingFunc)(candidate));
                    }

                    if(promiseAllArray.length > 0){
                        candidates = await Promise.all(promiseAllArray);
                    }
                    //monitor all candidates
                    promiseAllArray = [];
                    for(candidate of candidates){
                        promiseAllArray.push((this.addInstanceToMonitor)(candidate));
                    }
                    candidateMonitored = await Promise.all(promiseAllArray);
                }

                if(master){
                    parameters = {
                        resourceGroup: process.env.RESOURCE_GROUP,
                        scaleSetName: process.env.SCALESET_NAME,
                        virtualMachineId: instanceId
                    };
                    virtualMachine = await this.platform.describeInstance(parameters);
                    return await this.updateMaster(virtualMachine);
                }
                else
                    return Promise.reject(`No instance available for master.`);
            }

            async monitorElection(){
                //monitor these:
                //1. if a master is created
                //2. if the mutex is released
                //logic:
                //if master is created, read the master and 
                //compare its ip with self ip to determine which config to return.
                //if master is not created but mutex is released, switch to hold another election
                return await this.holdMasterElection(null);
            }

            async updateMaster(instance){
                logger.info(`calling updateMaster`);
                let documentContent = {
                    master: 'master',
                    ip: instance.getPrimaryPrivateIp(),
                    instanceId: instance.instanceId,
                    vmId: instance.properties.vmId
                };

                let documentId = `${scaleSetName}-master`,
                    replaced = true;
                try{
                    let doc = await azureApiCosmosDBCreateDocument(process.env.SCALESET_DB_ACCOUNT, databaseName, dbCollectionMaster, documentId,
                        documentContent, replaced, masterKey);
                    if(doc){
                        logger.info(`called updateMaster: master(id:${documentContent.instanceId}, ip: ${documentContent.ip}) updated.`);
                        return true;
                    }
                    else{
                        logger.error(`called updateMaster: master(id:${documentContent.instanceId}, ip: ${documentContent.ip}) not updated.`);
                        return false;
                    }
                }
                catch(error){
                    logger.error(`updateMaster > error: ${error}`);
                    return false;
                }
            }

            async addInstanceToMonitor(instance){
                logger.info(`calling addInstanceToMonitor`);
                let documentContent = {
                    ip: instance.getPrimaryPrivateIp(),
                    instanceId: instance.instanceId,
                    vmId: instance.properties.vmId,
                    scaleSetName: process.env.SCALESET_NAME
                };

                let documentId = instance.properties.vmId,
                    replaced = true;
                try{
                    let doc = await azureApiCosmosDBCreateDocument(process.env.SCALESET_DB_ACCOUNT, databaseName, dbCollectionMonitored, documentId,
                        documentContent, replaced, masterKey);
                    if(doc){
                        logger.info(`called addInstanceToMonitor: ${documentId} monitored.`);
                        return true;
                    }
                    else{
                        logger.error(`called addInstanceToMonitor: ${documentId} not monitored.`);
                        return false;
                    }
                }
                catch(error){
                    logger.error(`addInstanceToMonitor > error: ${error}`);
                    return false;
                }
            }

            async listMonitoredInstances(){
                const queryObject = {
                    query: `SELECT * FROM ${dbCollectionMonitored} c WHERE c.scaleSetName = @scaleSetName`,
                    parameters: [
                        {
                            "name": "@scaleSetName",
                            "value": `${scaleSetName}`
                        }
                    ]
                };

                try {
                    let instances = {}, docs = await azureApiCosmosDbQuery(process.env.SCALESET_DB_ACCOUNT, {
                        dbName: databaseName,
                        collectionName: dbCollectionMonitored,
                        partitioned: true,
                        queryObject: queryObject
                    }, masterKey);
                    if(Array.isArray(docs)){
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

            async getCallingInstanceIdentifier(request){
                //TODO: hardcode alert! for testing use
                if(request.headers && request.headers['client-ip']){
                    return request.headers['client-ip'];
                }
            }

            async getMasterInfo(){
                const queryObject = {
                    query: `SELECT * FROM ${dbCollectionMaster} c WHERE c.id = @id`,
                    parameters: [
                        {
                            "name": "@id",
                            "value": `${scaleSetName}-master`
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

            async AcquireMutex(collectionName){
                let _mutex = null, _purge = false,_now = Math.floor(Date.now() / 1000);
                let _getMutex = async function(collectionName){
                    const queryObject = {
                        query: `SELECT * FROM ${dbCollectionMutex} c WHERE c.collectionName = @collectionName`,
                        parameters: [
                            {
                                "name": "@collectionName",
                                "value": `${collectionName}`
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
                        _mutex = docs[0];
                    } catch (error) {
                        _mutex = null;
                        logger.error(error);
                    }
                    return _mutex;
                }
                
                let _createMutex = async function(collectionName, purge){
                    logger.info(`calling _createMutex`);
                    let documentContent = {
                        servingStatus: 'activated',
                        collectionName: collectionName,
                        acquireLocalTime: _now
                    };
    
                    let documentId = uuidGenerator(JSON.stringify(documentContent) + ___request_uuid),
                        replaced = false;
                    try{
                        if(purge && _mutex){
                            await azureApiCosmosDBDeleteDocument(process.env.SCALESET_DB_ACCOUNT, databaseName, dbCollectionMutex, _mutex.id, masterKey);
                        }
                        let doc = await azureApiCosmosDBCreateDocument(process.env.SCALESET_DB_ACCOUNT, databaseName, dbCollectionMutex, documentId,
                            documentContent, replaced, masterKey);
                        if(doc){
                            _mutex = doc;
                            logger.info(`called _createMutex: mutex(${collectionName}) created.`);
                            return true;
                        }
                        else{
                            logger.warn(`called _createMutex: mutex(${collectionName}) not created.`);
                            return true;
                        }
                    }
                    catch(error){
                        logger.error(`_createMutex > error: ${error}`);
                        return false;
                    }
                }

                await _getMutex(collectionName);
                //mutex should last no more than 5 minute (Azure function default timeout)
                if(_mutex && _now - _mutex.acquireLocalTime > 300){
                    //purge the dead mutex
                    _purge = true;
                }
                //no mutex?
                if(!_mutex || _purge){
                    //create one
                    let created = await _createMutex(collectionName, _purge);
                    if(!created){
                        throw new Error(`Error in acquiring mutex(${collectionName})`);
                    }
                    return _mutex;
                }
                else{
                    return null;
                }
            }

            async releaseMutex(collectionName, mutex){
                logger.info(`calling releaseMutex: mutex(${collectionName}, ${mutex.id}).`);
                let documentId = mutex.id;
                try{
                    let deleted = await azureApiCosmosDBDeleteDocument(process.env.SCALESET_DB_ACCOUNT, databaseName, dbCollectionMutex, documentId, masterKey);
                    if(deleted){
                        logger.info(`called releaseMutex: mutex(${collectionName}) released.`);
                        return true;
                    }
                    else{
                        logger.warn(`called releaseMutex: mutex(${collectionName}) not found.`);
                        return true;
                    }
                }
                catch(error){
                    logger.info(`releaseMutex > error: ${error}`);
                    return false;
                }
            }
        }
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

            async handle() {
                throw new Error('Not Implemented')
            }

            async init() {
                await this.platform.init();
            }

            async getConfig(ip) {
                this.step = 'handler:getConfig:holdElection';
                const
                    masterIp = await this.holdMasterElection(ip);
                if (masterIp == ip) {

                    this.step = 'handler:getConfig:completeMaster';
                    await this.completeMasterInstance(await this.platform.findInstanceIdByIp(ip));

                    this.step = 'handler:getConfig:getMasterConfig';
                    return await this.getMasterConfig();
                } else {

                    this.step = 'handler:getConfig:getSlaveConfig';
                    return await this.getSlaveConfig(masterIp);
                }
            }

            async getMasterConfig() {
                return this._baseConfig.replace(/\$\{CALLBACK_URL}/,
                    await this.platform.getApiGatewayUrl());
            }

            async getSlaveConfig(masterIp) {
                const
                    autoScaleSectionMatch = AUTOSCALE_SECTION_EXPR
                    .exec(await this._baseConfig),
                    autoScaleSection = autoScaleSectionMatch && autoScaleSectionMatch[1],
                    matches = [
                        /set\s+sync-interface\s+(.+)/.exec(autoScaleSection),
                        /set\s+psksecret\s+(.+)/.exec(autoScaleSection),
                    ];
                const [syncInterface, pskSecret] = matches.map(m => m && m[1]),
                    apiEndpoint = await this.platform.getApiGatewayUrl(),
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
                    throw new Error('Base config is invalid: ' +
                        JSON.stringify({
                            syncInterface,
                            apiEndpoint,
                            masterIp,
                            pskSecret: pskSecret && typeof pskSecret
                        }));
                }
                if (!apiEndpoint) {
                    throw new Error('Api endpoint is missing');
                }
                if (!masterIp) {
                    throw new Error('Master ip is missing');
                }
                // console.log('Slave config: ', config.replace(SET_SECRET_EXPR, '$1 *'));
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
        }

        return AutoscaleHandler;
    }

    function getAzurePlatform(CloudPlatform, LifecycleItem) {
        const
            armClient = getAzureArmClient();
        return class AzurePlatform extends CloudPlatform {
            async init() {
                let _initDB = async function(){
                    return azureApiCosmosDBCreateDB(process.env.SCALESET_DB_ACCOUNT, databaseName, masterKey)
                    .then((status)=>{
                        if(status === true){
                            return Promise.all([
                                //create instances
                                azureApiCosmosDBCreateCollection(process.env.SCALESET_DB_ACCOUNT, databaseName, dbCollectionMonitored, masterKey),
                                azureApiCosmosDBCreateCollection(process.env.SCALESET_DB_ACCOUNT, databaseName, dbCollectionMaster, masterKey),
                                azureApiCosmosDBCreateCollection(process.env.SCALESET_DB_ACCOUNT, databaseName, dbCollectionMutex, masterKey)
                            ]);
                        }
                        else{
                            logger.info(`DB exists. Skip creating collections.`);
                            return true;
                        }
                    });
                }

                await Promise.all([
                    _initDB(),
                    armClient.authWithServicePrincipal(process.env.REST_APP_ID, process.env.REST_APP_SECRET, process.env.TENANT_ID)]);
                    armClient.useSubscription(process.env.SUBSCRIPTION_ID);
            }

            // unfortunately we can't link up the api gateway id during CFT stack creation as it
            // would create a cycle. Grab it by looking up the rest api name passed as a parameter
            async getApiGatewayUrl() {
                //TODO: is it safe to use the context.req.originalUrl as the api gateway?
                return ___context.req.originalUrl;
            }

            async findInstanceIdByIp(localIp) {
                let instance = await armClient.ComputeClient.VirtualMachineScaleSets.getVirtualMachineByIp(process.env.RESOURCE_GROUP, process.env.SCALESET_NAME, localIp);

                if (instance.networkInterface) {
                    return instance.networkInterface.properties.ipConfigurations[0].properties.privateIPAddress;
                } else return null;
            }

            async protectInstanceFromScaleIn(item, protect = true) {
                //TODO: look for a solution here.
                logger.warn(`called putPendingLifecycleAction: but not implemented.`);
                return false;
            }

            async listAllInstances(parameters){
                logger.info(`calling listAllInstances`);
                let virtualMachines = await armClient.ComputeClient.VirtualMachineScaleSets.listVirtualMachines(parameters.resourceGroup, parameters.scaleSetName);
                logger.info(`called listAllInstances`);
                return virtualMachines;
            }
            
            async describeInstance(parameters){
                logger.info(`calling describeInstance`);
                let virtualMachine = await armClient.ComputeClient.VirtualMachineScaleSets.getVirtualMachine(parameters.resourceGroup, parameters.scaleSetName, parameters.virtualMachineId);
                logger.info(`called describeInstance`);
                
                return (function(vm){
                    vm.getPrimaryPrivateIp = ()=>{
                        for(let networkInterface of vm.properties.networkProfile.networkInterfaces){
                            if(networkInterface.properties.primary){
                                for(let ipConfiguration of networkInterface.properties.ipConfigurations){
                                    if(ipConfiguration.properties.primary){
                                        return ipConfiguration.properties.privateIPAddress;
                                    }
                                }
                            }
                        }
                        return null;
                    };
                    return vm;
                })(virtualMachine);
            }
        }
    }
}