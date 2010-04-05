var saslc = require('./lib/binding_sasl');
var sys = require('sys');

exports.createSaslConnection = function() {
    var serv = new saslc.ServerConnection();
    serv.mechanisms = JSON.parse( serv._mechanisms() );
    return serv;
}
