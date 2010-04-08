var sasl = require('./sasl');
var sys = require('sys');

sasl_conn = sasl.createSaslConnection();
sys.debug( sys.inspect( sasl_conn.mechanisms ) );
sys.debug( sys.inspect( sasl ) );

sys.debug("---------- START --------- ");
var res = sasl_conn.start( "DIGEST-MD5" );
sys.debug(sys.inspect(res));

res = sasl_conn.step("");
sys.debug(sys.inspect(res));
