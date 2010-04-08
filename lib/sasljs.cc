/*
 * Copyright 2010, Nikhil Marathe <nsm.nikhil@gmail.com> All rights reserved.
 * See LICENSE for details.
*/
#include "sasljs.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>

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
  v8::HandleScope scope;

  v8::Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(New);

  t->InstanceTemplate()->SetInternalFieldCount(1);

  NODE_DEFINE_CONSTANT( target, GSASL_OK  );
  NODE_DEFINE_CONSTANT( target, GSASL_NEEDS_MORE  );
  NODE_DEFINE_CONSTANT( target, GSASL_UNKNOWN_MECHANISM  );
  NODE_DEFINE_CONSTANT( target, GSASL_MECHANISM_CALLED_TOO_MANY_TIMES  );
  NODE_DEFINE_CONSTANT( target, GSASL_MALLOC_ERROR  );
  NODE_DEFINE_CONSTANT( target, GSASL_BASE64_ERROR  );
  NODE_DEFINE_CONSTANT( target, GSASL_CRYPTO_ERROR  );
  NODE_DEFINE_CONSTANT( target, GSASL_SASLPREP_ERROR  );
  NODE_DEFINE_CONSTANT( target, GSASL_MECHANISM_PARSE_ERROR  );
  NODE_DEFINE_CONSTANT( target, GSASL_AUTHENTICATION_ERROR  );
  NODE_DEFINE_CONSTANT( target, GSASL_INTEGRITY_ERROR  );
  NODE_DEFINE_CONSTANT( target, GSASL_NO_CLIENT_CODE  );
  NODE_DEFINE_CONSTANT( target, GSASL_NO_SERVER_CODE  );
  NODE_DEFINE_CONSTANT( target, GSASL_NO_CALLBACK  );
  NODE_DEFINE_CONSTANT( target, GSASL_NO_ANONYMOUS_TOKEN  );
  NODE_DEFINE_CONSTANT( target, GSASL_NO_AUTHID  );
  NODE_DEFINE_CONSTANT( target, GSASL_NO_AUTHZID  );
  NODE_DEFINE_CONSTANT( target, GSASL_NO_PASSWORD  );
  NODE_DEFINE_CONSTANT( target, GSASL_NO_PASSCODE  );
  NODE_DEFINE_CONSTANT( target, GSASL_NO_PIN  );
  NODE_DEFINE_CONSTANT( target, GSASL_NO_SERVICE  );
  NODE_DEFINE_CONSTANT( target, GSASL_NO_HOSTNAME  );
  NODE_DEFINE_CONSTANT( target, GSASL_GSSAPI_RELEASE_BUFFER_ERROR  );
  NODE_DEFINE_CONSTANT( target, GSASL_GSSAPI_IMPORT_NAME_ERROR  );
  NODE_DEFINE_CONSTANT( target, GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR  );
  NODE_DEFINE_CONSTANT( target, GSASL_GSSAPI_ACCEPT_SEC_CONTEXT_ERROR  );
  NODE_DEFINE_CONSTANT( target, GSASL_GSSAPI_UNWRAP_ERROR  );
  NODE_DEFINE_CONSTANT( target, GSASL_GSSAPI_WRAP_ERROR  );
  NODE_DEFINE_CONSTANT( target, GSASL_GSSAPI_ACQUIRE_CRED_ERROR  );
  NODE_DEFINE_CONSTANT( target, GSASL_GSSAPI_DISPLAY_NAME_ERROR  );
  NODE_DEFINE_CONSTANT( target, GSASL_GSSAPI_UNSUPPORTED_PROTECTION_ERROR  );
  NODE_DEFINE_CONSTANT( target, GSASL_KERBEROS_V5_INIT_ERROR  );
  NODE_DEFINE_CONSTANT( target, GSASL_KERBEROS_V5_INTERNAL_ERROR  );
  NODE_DEFINE_CONSTANT( target, GSASL_SHISHI_ERROR );
  NODE_DEFINE_CONSTANT( target, GSASL_SECURID_SERVER_NEED_ADDITIONAL_PASSCODE  );
  NODE_DEFINE_CONSTANT( target, GSASL_SECURID_SERVER_NEED_NEW_PIN  );

  NODE_SET_PROTOTYPE_METHOD( t, "_mechanisms", GetMechanisms );
  NODE_SET_PROTOTYPE_METHOD( t, "start", Start );
  NODE_SET_PROTOTYPE_METHOD( t, "step", Step );

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
  ServerConnection *server = new ServerConnection( "xmpp", "localhost" );
  server->Wrap( args.This() );
  return args.This();
}

ServerConnection::ServerConnection( const char *service, const char *realm )
  : ObjectWrap()
  , m_session( NULL )
{
}

ServerConnection::~ServerConnection()
{
}

Handle<Value>
ServerConnection::GetMechanisms( const v8::Arguments &args )
{
  ServerConnection *sc = Unwrap<ServerConnection>( args.This() );

  char *result;
  
  int mechres = gsasl_server_mechlist( ctx, &result );
  if( mechres != GSASL_OK ) {
    return String::New( "" );
  }

  Handle<String> ret = String::New( result, strlen( result ) );
  free( result );
  return ret;
}

static int
callback( Gsasl *ctx, Gsasl_session *sctx, Gsasl_property prop )
{
  std::cerr << "!!!!!!!!!! Callback called with property " << prop << std::endl;
  char buf[500];
  switch( prop ) {
    case GSASL_REALM:
      strcpy(buf, "localhost");
      gsasl_property_set( sctx, GSASL_REALM, buf );
      return GSASL_OK;

    case GSASL_PASSWORD:
      gsasl_property_set( sctx, GSASL_PASSWORD, "1234" );
      return GSASL_OK;
  }

  return GSASL_NO_CALLBACK;
}

/**
 * Returns a map
 * { status: integer_error_code,
 *   data : data to send to client if error == GSASL_OK }
 */
v8::Handle<v8::Value>
ServerConnection::Start( const v8::Arguments &args )
{
  REQ_STR_ARG( 0, mechanismString );

  int res;

  ServerConnection *sc = Unwrap<ServerConnection>( args.This() );
  if( sc->m_session != NULL ) {
    return ThrowException( Exception::Error( String::New( "sasljs: This session is already started!" ) ) );
  }

  gsasl_callback_set( ctx, callback );
  res = gsasl_server_start( ctx, *mechanismString, &sc->m_session );

  return Integer::New( res );
}

v8::Handle<v8::Value>
ServerConnection::Step( const v8::Arguments &args )
{
  REQ_STR_ARG( 0, clientinString );

  ServerConnection *sc = Unwrap<ServerConnection>( args.This() );

  char *reply;
  size_t len;

  char *b64;
  size_t crap;
  gsasl_base64_from( *clientinString, strlen( *clientinString ), &b64, &crap );
  std::cerr << std::endl << "sasljs: step: " << b64 << std::endl;

  gsasl_base64_from( *clientinString, strlen(*clientinString), &reply, &len );
  int res = gsasl_step64( sc->m_session, *clientinString, &reply );

  Handle<Object> obj = Object::New();
  Local<String> status = String::New( "status" );

  char *d64;
  gsasl_base64_from( reply, strlen(reply), &d64, &len );
  std::cerr << std::endl << "sasljs: step OUT: " << d64 << std::endl;

  if( res == GSASL_OK || res == GSASL_NEEDS_MORE ) {
    obj->Set( status, Integer::New( res ) );
    obj->Set( String::New( "data" ), String::New( reply, strlen( reply ) ) );

    return obj;
  }
  else {
    obj->Set( status, Integer::New( res ) );
    obj->Set( String::New( "data" ), String::New( gsasl_strerror( res ) ) );
    return obj;
  }
}
}

extern "C" void
init (Handle<Object> target)
{
  HandleScope scope;

  sasljs::ctx = NULL;
  int initres = gsasl_init( &sasljs::ctx );

  if( initres != GSASL_OK ) {
      fprintf( stderr, "Could not initialize gsasl: %s\n", gsasl_strerror( initres ) );
      abort();
  }

  sasljs::ServerConnection::Initialize(target);
}
