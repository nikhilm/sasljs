/*
 * Copyright 2010, Nikhil Marathe <nsm.nikhil@gmail.com> All rights reserved.
 * See LICENSE for details.
*/
#include "sasljs.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

using namespace v8;
using namespace node;

/*
 * Macro from the sqlite3 bindings
 * http://github.com/grumdrig/node-sqlite/blob/master/sqlite3_bindings.cc
 * by Eric Fredricksen
 */
#define REQ_STR_ARG(I, VAR)                                             \
      if (args.Length() <= (I) || !args[I]->IsString())                     \
    return ThrowException(Exception::TypeError(                         \
                                  String::New("Argument " #I " must be a string"))); \
  String::Utf8Value VAR(args[I]->ToString());

namespace sasljs {
void ServerConnection::Initialize ( Handle<Object> target )
{
    int initres = sasl_server_init( NULL, "sasljs" );
    if( initres != SASL_OK ) {
        const char *err = sasl_errstring( initres, NULL, NULL );
        fprintf( stderr, "Could not initialize libsasl: %s\n", err );
        abort();
    }

    v8::HandleScope scope;

    v8::Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(New);

    t->InstanceTemplate()->SetInternalFieldCount(1);

    NODE_DEFINE_CONSTANT( target, SASL_CONTINUE );
    NODE_DEFINE_CONSTANT( target, SASL_OK );
    NODE_DEFINE_CONSTANT( target, SASL_FAIL );
    NODE_DEFINE_CONSTANT( target, SASL_NOMEM );
    NODE_DEFINE_CONSTANT( target, SASL_BUFOVER );
    NODE_DEFINE_CONSTANT( target, SASL_NOMECH );
    NODE_DEFINE_CONSTANT( target, SASL_BADPROT );
    NODE_DEFINE_CONSTANT( target, SASL_NOTDONE );
    NODE_DEFINE_CONSTANT( target, SASL_BADPARAM );
    NODE_DEFINE_CONSTANT( target, SASL_TRYAGAIN );
    NODE_DEFINE_CONSTANT( target, SASL_BADMAC );
    NODE_DEFINE_CONSTANT( target, SASL_NOTINIT );
    NODE_DEFINE_CONSTANT( target, SASL_BADAUTH );
    NODE_DEFINE_CONSTANT( target, SASL_NOAUTHZ );
    NODE_DEFINE_CONSTANT( target, SASL_TOOWEAK );
    NODE_DEFINE_CONSTANT( target, SASL_ENCRYPT );
    NODE_DEFINE_CONSTANT( target, SASL_TRANS );
    NODE_DEFINE_CONSTANT( target, SASL_EXPIRED );
    NODE_DEFINE_CONSTANT( target, SASL_DISABLED );
    NODE_DEFINE_CONSTANT( target, SASL_NOUSER );
    NODE_DEFINE_CONSTANT( target, SASL_BADVERS );
    NODE_DEFINE_CONSTANT( target, SASL_UNAVAIL );
    NODE_DEFINE_CONSTANT( target, SASL_NOVERIFY );
    NODE_DEFINE_CONSTANT( target, SASL_PWLOCK );
    NODE_DEFINE_CONSTANT( target, SASL_NOCHANGE );
    NODE_DEFINE_CONSTANT( target, SASL_WEAKPASS );
    NODE_DEFINE_CONSTANT( target, SASL_NOUSERPASS );

    NODE_SET_PROTOTYPE_METHOD( t, "_mechanisms", GetMechanisms );

    target->Set( v8::String::NewSymbol( "ServerConnection"), t->GetFunction() );
}

/*
 * Call in JS
 * new ServerConnection( "service name" );
 * All other options default to NULL for now
 */
v8::Handle<v8::Value>
ServerConnection::New (const v8::Arguments& args)
{
    HandleScope scope;

    // TODO get service, realm from args
    ServerConnection *server = new ServerConnection( "", "ironik" );
    server->Wrap( args.This() );
    return args.This();
}

ServerConnection::ServerConnection( const char *service, const char *realm )
  : ObjectWrap()
{
    int res = sasl_server_new( service,
                               NULL,
                               NULL,
                               NULL,
                               NULL,
                               NULL,
                               0,
                               &m_sasl );
    if( res != SASL_OK ) {
        const char *err = sasl_errstring( res, NULL, NULL );
        fprintf( stderr, "sasljs: %s\n", err );
        abort();
    }
}

ServerConnection::~ServerConnection()
{
    sasl_dispose( &m_sasl );
}

/*
 * Returns a JSON list so that it can be easily
 * converted in JavaScript.
 */
Handle<Value>
ServerConnection::GetMechanisms( const v8::Arguments &args )
{
    ServerConnection *sc = Unwrap<ServerConnection>( args.This() );

    const char *result;
    unsigned int len;
    int err = sasl_listmech( sc->m_sasl,
                              NULL,
                              "[\"",
                              "\",\"",
                              "\"]",
                              &result,
                              &len,
                              NULL );
    if( err != SASL_OK ) {
        return ThrowException( Exception::Error( String::New( "sasljs: Error getting mechanism list" ) ) );
    }

    return String::New( result, len );
}
}

extern "C" void
init (Handle<Object> target)
{
    HandleScope scope;
    sasljs::ServerConnection::Initialize(target);
}
