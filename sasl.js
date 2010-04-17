var saslc = require('./lib/binding_sasl');
var sys = require('sys');

Object.keys(saslc).forEach(function(elt) {
    if( typeof(saslc[elt]) == "number" )
        exports[elt] = saslc[elt];
});

exports.createServerSession = function(realm, callback) {
    var serv = new saslc.ServerSession( realm, callback );
    serv.mechanisms = serv._mechanisms().split(' ');
    // POP empty element
    serv.mechanisms.pop();
    return serv;
}
