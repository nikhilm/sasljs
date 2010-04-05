var sasl = require('./sasl');
var sys = require('sys');

sasl_conn = sasl.createSaslConnection();
sys.debug( sys.inspect( sasl_conn.mechanisms ) );
sys.debug( sys.inspect( sasl ) );

var res= sasl_conn.start( "dXNlcm5hbWU9InNvbWVub2RlIixyZWFsbT0ic29tZXJlYWxtIixub25jZT0iT0E2TUc5dEVRR20yaGgiLGNub25jZT0iT0E2TUhYaDZWcVRyUmsiLG5jPTAwMDAwMDAxLHFvcD1hdXRoLGRpZ2VzdC11cmk9InhtcHAvZXhhbXBsZS5jb20iLHJlc3BvbnNlPWQzODhkYWQ5MGQ0YmJkNzYwYTE1MjMyMWYyMTQzYWY3LGNoYXJzZXQ9dXRmLTgK", "DIGEST-MD5" ) ;


sys.debug(sys.inspect(res));
