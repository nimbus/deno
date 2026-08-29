// Copyright 2018-2026 the Deno authors. MIT license.

use std::sync::Arc;

use deno_core::OpState;
use deno_core::url::Url;
use deno_error::JsErrorBox;
use deno_fetch::EgressGatewayAuthorization;
use deno_fetch::EgressGatewayRequest;
use deno_fetch::EgressGatewayTransport;
use deno_fetch::Options as FetchOptions;
use deno_permissions::Permissions;
use deno_permissions::PermissionsContainer;
use deno_permissions::PermissionsOptions;
use deno_permissions::RuntimePermissionDescriptorParser;

use super::WebsocketError;
use super::WsCancelResource;
use super::check_permission_and_cancel_handle;
use super::ensure_custom_client_can_apply_egress_authorization;

fn allow_with_deno_permissions(
  _state: &mut OpState,
  request: EgressGatewayRequest<'_>,
) -> Result<EgressGatewayAuthorization, JsErrorBox> {
  assert_eq!(request.transport, EgressGatewayTransport::WebSocket);
  Ok(EgressGatewayAuthorization::use_deno_permissions())
}

fn allow_without_deno_permissions(
  _state: &mut OpState,
  request: EgressGatewayRequest<'_>,
) -> Result<EgressGatewayAuthorization, JsErrorBox> {
  assert_eq!(request.transport, EgressGatewayTransport::WebSocket);
  Ok(EgressGatewayAuthorization::bypass_deno_permissions())
}

fn deny_websocket_egress(
  _state: &mut OpState,
  request: EgressGatewayRequest<'_>,
) -> Result<EgressGatewayAuthorization, JsErrorBox> {
  assert_eq!(request.transport, EgressGatewayTransport::WebSocket);
  Err(JsErrorBox::generic("blocked by WebSocket egress gateway"))
}

fn deny_net_permissions(deny: &[&str]) -> PermissionsContainer {
  let parser =
    RuntimePermissionDescriptorParser::new(sys_traits::impls::RealSys);
  let permissions = Permissions::from_options(
    &parser,
    &PermissionsOptions {
      allow_net: Some(vec![]),
      deny_net: Some(deny.iter().map(|value| value.to_string()).collect()),
      ..Default::default()
    },
  )
  .expect("deny-net permissions should build");
  PermissionsContainer::new(Arc::new(parser), permissions)
}

#[test]
fn websocket_gateway_deno_permission_denial_is_returned() {
  let mut state = OpState::new(None);
  state.put(FetchOptions {
    egress_gateway_hook: Some(allow_with_deno_permissions),
    ..Default::default()
  });
  state.put(deny_net_permissions(&["example.com"]));

  let error = check_permission_and_cancel_handle(
    &mut state,
    "new WebSocket()".to_string(),
    "wss://example.com/socket".to_string(),
    None,
  )
  .expect_err(
    "Deno net permission denial should reject WebSocket authorization",
  );

  assert!(matches!(error, WebsocketError::Permission(_)));
}

#[test]
fn websocket_gateway_denial_precedes_permission_state() {
  let mut state = OpState::new(None);
  state.put(FetchOptions {
    egress_gateway_hook: Some(deny_websocket_egress),
    ..Default::default()
  });

  let error = check_permission_and_cancel_handle(
    &mut state,
    "new WebSocket()".to_string(),
    "wss://example.com/socket".to_string(),
    None,
  )
  .expect_err("egress gateway denial should reject before permission lookup");

  assert!(matches!(error, WebsocketError::Other(_)));
  assert_eq!(error.to_string(), "blocked by WebSocket egress gateway");
}

#[test]
fn websocket_gateway_bypass_is_bound_to_url_and_client() {
  let mut state = OpState::new(None);
  state.put(FetchOptions {
    egress_gateway_hook: Some(allow_without_deno_permissions),
    ..Default::default()
  });
  let authorized_url = "wss://example.com/socket";
  let rid = check_permission_and_cancel_handle(
    &mut state,
    "new WebSocket()".to_string(),
    authorized_url.to_string(),
    Some(42),
  )
  .expect("gateway bypass should not require a permissions container");
  let resource = state
    .resource_table
    .get::<WsCancelResource>(rid)
    .expect("cancel resource should remain available");
  let authorized_url = Url::parse(authorized_url).unwrap();

  assert!(
    !resource
      .authorization_for(&authorized_url, Some(42))
      .expect("the exact authorized target should match")
      .use_deno_client_permissions
  );
  assert!(
    resource
      .authorization_for(
        &Url::parse("wss://other.example/socket").unwrap(),
        Some(42),
      )
      .is_err()
  );
  assert!(
    resource
      .authorization_for(&authorized_url, Some(43))
      .is_err()
  );
}

#[test]
fn custom_websocket_client_rejects_checker_but_can_remain_stricter() {
  ensure_custom_client_can_apply_egress_authorization(
    Some(42),
    &EgressGatewayAuthorization::bypass_deno_permissions(),
  )
  .expect("checker-less custom client may retain stricter Deno permissions");

  let authorization = EgressGatewayAuthorization::use_deno_permissions()
    .with_resolved_address_checker(
      deno_fetch::dns::ResolvedAddressChecker::new(|_, _| Ok(())),
    );
  let error = ensure_custom_client_can_apply_egress_authorization(
    Some(42),
    &authorization,
  )
  .expect_err("custom client must not drop the resolved-address checker");

  assert!(
    error.to_string().contains(
      "custom WebSocket client cannot apply the egress gateway authorization"
    ),
    "custom-client rejection should identify the unavailable enforcement seam: {error}"
  );
}
