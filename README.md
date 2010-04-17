SASL
====

Bindings to [GSASL](http://www.gnu.org/software/gsasl/) for node.js.
Made to implement XMPP, but can be used anywhere.

At the moment the only plan is to support basic server side auth with callbacks

Since I do not currently require any other parts of the SASL API, they will not be implemented.
You are welcome to add them though, please notify me when you do, so that I can pull.

Usage
-----

1) Create a new SASL session using

    var sasl = require('sasljs');
    var session = sasl.createServerSession("<realm>",
    callback );

`callback` is a callback function which should accept
the property name and session object and set
properties as requested.

2) Start the session with a mechanism. The list of
supported mechanisms is available as
`session.mechanisms`.

    session.start("DIGEST-MD5");

3) Step through the authentication procedure by
calling `step()` with input from the client.

    session.step("<client input>");

`step()` returns an object with two members:

    {
        status: Integer status code,
        data: Error or reply
    }

If `status` is `sasl.GSASL_OK`, authentication
succeeded. For `sasl.GSASL_NEEDS_MORE` send the data
back to the client. For others, compare against
available error codes and decide what to do. Usually
abort.

4) Use callback

    function callback(property, session) {
        // since realm is not currently set above
        if( property == sasl.GSASL_REALM ) {
            session.setProperty("realm", "MyHomePage");
            return sasl.GSASL_OK;
        }

        if( property == sasl.GSASL_PASSWORD ) {
            // get password for user, using property()
            var pass = getPassword(session.property('authid'));
            session.setProperty('password', pass);
            return sasl.GSASL_OK;
        }
    }

You *have* to return `GSASL_OK` if you handled the callback!
As you can see, `setProperty()` accepts string keys. For a list
of keys, see `lib/sasljs.cc` towards the end.


----
Nikhil Marathe
