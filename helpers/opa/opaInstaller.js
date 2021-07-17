// Installs the opa engine based on the user OS
const os = require('os');
const fs = require('fs');
const request = require('request');
const { exec } = require('child_process');

var executeCommand = ( command, options, cb) => {
    exec(command, options, (err, stdout, stderr) => {
        if (err) {
            // node couldn't execute the command
            return cb(err, null, null);
        }
        return cb(null, stdout, stderr);
    });
};

// var downloadOPAforOscurl = () => {
//     var osType = os.type();
//     var command;
//     if ( osType === 'Windows_NT' ){
//         command = "curl -L -o opa.exe https://openpolicyagent.org/downloads/latest/opa_windows_amd64.exe";
//         // command = 'dir';
//     } else if ( osType === 'Linux' ){
//         //command = "curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64";
//         command = 'ls';
//     } else if ( osType === 'Darwin' ){
//         //command = "curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_darwin_amd64";
//         command = 'ls';
//     }
//     executeCommand(command, {}, (err) => {
//         if (err){
//             return console.error("Downloading opa failied for OS type " + osType + "with error " + err);
//         }
//     });
// };

var downloadOPAforOs = (callback) => {
    var osType = os.type();
    var opaurl;
    var opapath;
    if ( osType === 'Windows_NT' ){
        opaurl = 'https://openpolicyagent.org/downloads/latest/opa_windows_amd64.exe';
        opapath = 'opa.exe';
    } else if ( osType === 'Linux' ){
        opaurl = 'https://openpolicyagent.org/downloads/latest/opa_linux_amd64';
        opapath = 'opa';
    } else if ( osType === 'Darwin' ){
        opaurl = 'https://openpolicyagent.org/downloads/latest/opa_darwin_amd64';
        opapath = 'opa';
    }
    if (fs.existsSync(opapath)) {
        return callback();
    }
    const file = fs.createWriteStream(opapath);

    console.log('calling request');
    const sendReq = request.get(opaurl);

    // verify response code
    sendReq.on('response', (response) => {
        if (response.statusCode !== 200) {
            return callback('Response status was ' + response.statusCode);
        }
        sendReq.pipe(file);
    });

    // close() is async, call cb after close completes
    file.on('finish', () => file.close(callback));

    // check for request errors
    sendReq.on('error', (err) => {
        fs.unlink(opapath);
        return callback(err.message);
    });

    file.on('error', (err) => { // Handle errors
        fs.unlink(opapath); // Delete the file async. (But we don't check the result)
        return callback(err.message);
    });
};

// var getMetaData = function(plugin){
//     try {
//         var fsData = fs.readFileSync(plugin, 'utf8');
//         if (fsData.includes('__rego_metadata__')) {
//             var braces = [];
//             var metaData = [];
//             var meta = fsData.toString().split(':=');
//             var meta1 = meta[1];
//             for (let c of meta1) {
//                 if (c == '{') {
//                     braces.push(c);
//                     metaData.push(c);
//                 } else if (c == '}') {
//                     if (braces.length) {
//                         braces.pop();
//                         metaData.push(c);
//                         if (braces.length == 0) {
//                             break;
//                         }
//                     } else {
//                         return console.log('Malformed metadata');
//                     }
//                 } else {
//                     metaData.push(c);
//                 }
//             }
//             metaData = metaData.join('');
//             try {
//                 var metaDataobj = JSON.parse(metaData);
//                 return metaDataobj;
//             } catch (e) {
//                 return console.log("Error in parsing the metadata: " + e);
//             }
//         } else {
//             return console.error(" No metadata in the file specified");
//         }
//     } catch (e){
//         return console.error("Can not read the file:" + e);
//     }
//
// };

var getMetaData = function(pluginData){
    try {
        //var fsData = fs.readFileSync(plugin, 'utf8');
        if (pluginData.includes('__rego_metadata__')) {
            var braces = [];
            var metaData = [];
            var meta = pluginData.toString().split(':=');
            var meta1 = meta[1];
            for (let c of meta1) {
                if (c == '{') {
                    braces.push(c);
                    metaData.push(c);
                } else if (c == '}') {
                    if (braces.length) {
                        braces.pop();
                        metaData.push(c);
                        if (braces.length == 0) {
                            break;
                        }
                    } else {
                        return console.log('Malformed metadata');
                    }
                } else {
                    metaData.push(c);
                }
            }
            metaData = metaData.join('');
            try {
                var metaDataobj = JSON.parse(metaData);
                return metaDataobj;
            } catch (e) {
                return console.log('Error in parsing the metadata: ' + e);
            }
        } else {
            return console.error('No metadata in the file specified');
        }
    } catch (e){
        return console.error('Can not read the file:' + e);
    }

};
module.exports = {
    downloadOPAforOs: downloadOPAforOs,
    executeCommand: executeCommand,
    getMetaData: getMetaData
};
