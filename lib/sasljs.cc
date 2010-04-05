/*
 * Copyright 2010, Nikhil Marathe <nsm.nikhil@gmail.com> All rights reserved.
 * See LICENSE for details.
*/
#include "sasljs.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <sasl/saslutil.h>

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
  NODE_SET_PROTOTYPE_METHOD( t, "start", Start );

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

static int
encode_decode( const char *in, unsigned int inlen, char **out, unsigned int *len,
    int (func)( const char *, unsigned int, char *, unsigned int, unsigned int *) )
{
  // if it doesn't fit try doubling
  unsigned int size = 512;
  unsigned int outlen = 0;
  char *decode = (char *)malloc( sizeof(char) * size );

  int decoderes = SASL_OK;
  do {
    decoderes = func( in, inlen, decode, size, &outlen );
    if( decoderes == SASL_BADPROT )
      return decoderes;

    if( decoderes == SASL_BUFOVER ) {
      size = size * 2;
      if( realloc( decode, sizeof(char) * size ) == NULL ) {
        fprintf( stderr, "sasljs: Out of memory\n" );
        abort();
      }
    }
  } while( decoderes != SASL_OK );

  *out = decode;
  *len = outlen;

  return SASL_OK;
}

/*
 * Expects base64 encoded data
 * returns SASL_OK on success
 * SASL_BADPROT on bad data.
 * 
 * Remember to call free()
 */
static int 
decode_base64( const char *in, unsigned int inlen, char **out, unsigned int *len ) {
  return encode_decode( in, inlen, out, len, sasl_decode64 );
}

static int
encode_base64( const char *in, unsigned int inlen, char **out, unsigned int *len ) {
  return encode_decode( in, inlen, out, len, sasl_encode64 );
}

/**
 * Returns a map
 * { status: integer_error_code,
 *   data : data to send to client if error == SASL_OK }
 */
v8::Handle<v8::Value>
ServerConnection::Start( const v8::Arguments &args )
{
  REQ_STR_ARG( 0, clientinString );
  REQ_STR_ARG( 1, mechanismString );

  const char *clientin = *clientinString;

  char *output;
  unsigned int outlen = 0;

  Handle<Object> obj = Object::New();
  Local<String> status = String::New( "status" );

  int res = decode_base64( clientin, clientinString.length(), &output, &outlen );

  if( res == SASL_BADPROT ) {
    obj->Set( status, Integer::New( SASL_BADPROT ) );
    return obj;
  }

  const char *serverout;
  unsigned int serveroutlen = 0;

  ServerConnection *sc = Unwrap<ServerConnection>( args.This() );
  res = sasl_server_start( sc->m_sasl, *mechanismString, output, outlen, &serverout, &serveroutlen );

  if( res == SASL_NOMECH ) {
    obj->Set( status, Integer::New( SASL_NOMECH ) );
    return obj;
  }

  if( res == SASL_OK || res == SASL_CONTINUE ) {
    char *encoded = NULL;
    unsigned int enclen;
    if( encode_base64( serverout, serveroutlen, &encoded, &enclen ) != SASL_OK ) {
      obj->Set( status, Integer::New( SASL_BUFOVER ) );
      return obj;
    }
    obj->Set( status, Integer::New( res ) );
    obj->Set( String::New( "data" ), String::New( encoded, enclen ) );

    return obj;
  }

  return Null();
}
}

extern "C" void
init (Handle<Object> target)
{
  HandleScope scope;
  sasljs::ServerConnection::Initialize(target);
}
