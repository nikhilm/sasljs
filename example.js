var sasl = require('./sasl');
var sys = require('sys');

sasl_conn = sasl.createSaslConnection();
sys.debug( sys.inspect( sasl_conn.mechanisms ) );
