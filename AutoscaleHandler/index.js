'use strict';

/*
Author: Fortinet
*/
/* eslint-disable */
process.env.REST_API_MASTER_KEY = '1ugjFq7oDT20ukeD81UhgviVEi74vbMUiQq7eMV52W1bx2gqqMpB36o31yJB3pR2lXdQvVwKqewBgID0PMJKKQ==';
process.env.SCALESET_DB_ACCOUNT = 'dchao-auto-scale';
process.env.SUBSCRIPTION_ID = '4f27b38c-ad3f-43d8-a9a3-01182e5e2f9a';
process.env.RESOURCE_GROUP = 'dchao-auto-scale-dev';
process.env.SCALESET_NAME = 'dchao-auto-scale-dev';
process.env.TENANT_ID = '942b80cd-1b14-42a1-8dcf-4b21dece61ba';
process.env.REST_APP_ID = '14dbd5c5-307e-4ea4-8133-68738141feb1';
process.env.REST_APP_SECRET = '6DjsdZwmKqIeEFTm/ppz44Ag74NEBXhDzvWz4EeaxYo=';
process.env.HEART_BEAT_LOSS_COUNT = 3;
process.env.FTGT_BASE_CONFIG = 'diag sys ha hadiff log enable\\n' +
'diag debug app hasync -1\\n' +
'diag debug enable\\n' +
'config system dns\\n' +
'    unset primary\\n' +
'    unset secondary\\n' +
'end\\n' +
'config system auto-scale\\n' +
'    set status enable\\n' +
'    set sync-interface port1\\n' +
'    set role master\\n' +
'    set callback-url ${CALLBACK_URL}\\n' +
'    set psksecret 12345678\\n' +
'end\n';
/* eslint-enable */

const FtntAutoScaleAzure = require('ftnt-autoscale-azure');
/**
 * Azure Function App Entry.
 * @param {Object} context Azure Function App runtime context
 * @param {Object} req request object from c
 */
module.exports = async function(context, req) {
    await FtntAutoScaleAzure.initModule();
    FtntAutoScaleAzure.handle(context, req);
};
