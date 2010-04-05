var saslc = require('./lib/binding_sasl');
var sys = require('sys');

process.mixin( exports, saslc );
exports.createSaslConnection = function() {
    var serv = new saslc.ServerConnection();
    serv.mechanisms = JSON.parse( serv._mechanisms() );
    return serv;
}
