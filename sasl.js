var saslc = require('./lib/binding_sasl');
var sys = require('sys');

exports.prototype = Object.create( saslc );
exports.createServerSession = function(realm, callback) {
    var serv = new saslc.ServerSession( realm, callback );
    serv.mechanisms = serv._mechanisms().split(' ');
    // POP empty element
    serv.mechanisms.pop();
    return serv;
}
