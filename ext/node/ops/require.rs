// Copyright 2018-2026 the Deno authors. MIT license.

use std::borrow::Cow;
use std::cell::RefCell;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;

use boxed_error::Boxed;
use deno_ast::EmitOptions;
use deno_ast::MediaType;
use deno_ast::ParseParams;
use deno_ast::ProgramRef;
use deno_ast::SourceMap;
use deno_ast::SourceMapOption;
use deno_ast::swc::ast::ArrowExpr;
use deno_ast::swc::ast::BindingIdent;
use deno_ast::swc::ast::BlockStmtOrExpr;
use deno_ast::swc::ast::CallExpr;
use deno_ast::swc::ast::Callee;
use deno_ast::swc::ast::Expr;
use deno_ast::swc::ast::ExprOrSpread;
use deno_ast::swc::ast::Ident;
use deno_ast::swc::ast::IdentName;
use deno_ast::swc::ast::Import;
use deno_ast::swc::ast::Lit;
use deno_ast::swc::ast::MemberExpr;
use deno_ast::swc::ast::MemberProp;
use deno_ast::swc::ast::Pat;
use deno_ast::swc::ast::Program;
use deno_ast::swc::ast::Str;
use deno_ast::swc::common::DUMMY_SP;
use deno_ast::swc::common::SyntaxContext;
use deno_ast::swc::common::comments::NoopComments;
use deno_ast::swc::ecma_visit::VisitMut;
use deno_ast::swc::ecma_visit::VisitMutWith;
use deno_core::FastString;
use deno_core::JsRuntimeInspector;
use deno_core::OpState;
use deno_core::op2;
use deno_core::url::Url;
use deno_error::JsErrorBox;
use deno_package_json::PackageJsonRc;
use deno_path_util::normalize_path;
use deno_path_util::url_from_file_path;
use deno_path_util::url_to_file_path;
use deno_permissions::PermissionsContainer;
use node_resolver::InNpmPackageChecker;
use node_resolver::NodeResolutionKind;
use node_resolver::NpmPackageFolderResolver;
use node_resolver::ResolutionMode;
use node_resolver::UrlOrPath;
use node_resolver::UrlOrPathRef;
use node_resolver::cache::NodeResolutionThreadLocalCache;
use node_resolver::errors::PackageJsonLoadError;
use sys_traits::FsMetadataValue;

use crate::ExtNodeSys;
use crate::NodeRequireLoaderRc;
use crate::NodeResolverRc;
use crate::PackageJsonResolverRc;

#[must_use = "the resolved return value to mitigate time-of-check to time-of-use issues"]
fn ensure_read_permission<'a>(
  state: &mut OpState,
  file_path: Cow<'a, Path>,
) -> Result<Cow<'a, Path>, JsErrorBox> {
  // Fast path: when read is fully granted there's nothing to check, so skip
  // fetching the loader and the per-call work it does (e.g. module graph
  // lookups) entirely.
  if state.borrow::<PermissionsContainer>().query_read_all() {
    return Ok(file_path);
  }
  let loader = state.borrow::<NodeRequireLoaderRc>().clone();
  let permissions = state.borrow_mut::<PermissionsContainer>();
  loader.ensure_read_permission(permissions, file_path)
}

fn js_conditions_to_cow(
  conditions: Option<Vec<String>>,
) -> Option<Vec<Cow<'static, str>>> {
  conditions.map(|conditions| {
    conditions
      .into_iter()
      .map(Cow::Owned)
      .collect::<Vec<Cow<'static, str>>>()
  })
}

#[derive(Debug, Boxed, deno_error::JsError)]
pub struct RequireError(pub Box<RequireErrorKind>);

#[derive(Debug, thiserror::Error, deno_error::JsError)]
pub enum RequireErrorKind {
  #[class(inherit)]
  #[error(transparent)]
  UrlParse(
    #[from]
    #[inherit]
    url::ParseError,
  ),
  #[class(inherit)]
  #[error(transparent)]
  Permission(#[inherit] JsErrorBox),
  #[class(generic)]
  #[properties(inherit)]
  #[error(transparent)]
  PackageExportsResolve(
    #[from] node_resolver::errors::PackageExportsResolveError,
  ),
  #[class(generic)]
  #[properties(inherit)]
  #[error(transparent)]
  PackageJsonLoad(#[from] node_resolver::errors::PackageJsonLoadError),
  #[class(generic)]
  #[properties(inherit)]
  #[error(transparent)]
  PackageImportsResolve(
    #[from] node_resolver::errors::PackageImportsResolveError,
  ),
  #[class(generic)]
  #[properties(inherit)]
  #[error(transparent)]
  FilePathConversion(#[from] deno_path_util::UrlToFilePathError),
  #[class(generic)]
  #[properties(inherit)]
  #[error(transparent)]
  UrlConversion(#[from] deno_path_util::PathToUrlError),
  #[class(inherit)]
  #[error(transparent)]
  Fs(
    #[from]
    #[inherit]
    deno_io::fs::FsError,
  ),
  #[class(inherit)]
  #[error(transparent)]
  Io(
    #[from]
    #[inherit]
    std::io::Error,
  ),
  #[class(inherit)]
  #[error(transparent)]
  ReadModule(
    #[from]
    #[inherit]
    JsErrorBox,
  ),
  #[class(inherit)]
  #[error(transparent)]
  UnableToGetCwd(UnableToGetCwdError),
}

#[derive(Debug, thiserror::Error, deno_error::JsError)]
#[error("Unable to get CWD")]
#[class(inherit)]
pub struct UnableToGetCwdError(#[source] pub std::io::Error);

#[op2]
pub fn op_require_init_paths() -> Vec<String> {
  // todo(dsherret): this code is node compat mode specific and
  // we probably don't want it for small mammal, so ignore it for now

  // let (home_dir, node_path) = if cfg!(windows) {
  //   (
  //     std::env::var("USERPROFILE").unwrap_or_else(|_| "".into()),
  //     std::env::var("NODE_PATH").unwrap_or_else(|_| "".into()),
  //   )
  // } else {
  //   (
  //     std::env::var("HOME").unwrap_or_else(|_| "".into()),
  //     std::env::var("NODE_PATH").unwrap_or_else(|_| "".into()),
  //   )
  // };

  // let mut prefix_dir = std::env::current_exe().unwrap();
  // if cfg!(windows) {
  //   prefix_dir = prefix_dir.join("..").join("..")
  // } else {
  //   prefix_dir = prefix_dir.join("..")
  // }

  // let mut paths = vec![prefix_dir.join("lib").join("node")];

  // if !home_dir.is_empty() {
  //   paths.insert(0, PathBuf::from(&home_dir).join(".node_libraries"));
  //   paths.insert(0, PathBuf::from(&home_dir).join(".nod_modules"));
  // }

  // let mut paths = paths
  //   .into_iter()
  //   .map(|p| p.to_string_lossy().into_owned())
  //   .collect();

  // if !node_path.is_empty() {
  //   let delimiter = if cfg!(windows) { ";" } else { ":" };
  //   let mut node_paths: Vec<String> = node_path
  //     .split(delimiter)
  //     .filter(|e| !e.is_empty())
  //     .map(|s| s.to_string())
  //     .collect();
  //   node_paths.append(&mut paths);
  //   paths = node_paths;
  // }

  vec![]
}

#[op2(stack_trace)]
pub fn op_require_node_module_paths<TSys: ExtNodeSys + 'static>(
  state: &mut OpState,
  #[string] from: &str,
) -> Result<Vec<String>, RequireError> {
  let sys = state.borrow::<TSys>();
  // Guarantee that "from" is absolute. Avoid calling `env_current_dir()`
  // when we don't need it — on macOS it walks the directory tree from `/`
  // and fails with EACCES if any ancestor is unreadable (see #21585), so
  // an unrelated absolute `from` would otherwise crash here.
  let from_path = Path::new(from);
  let from = if from.starts_with("file:///") {
    Cow::Owned(url_to_file_path(&Url::parse(from)?)?)
  } else if from_path.is_absolute() {
    normalize_path(Cow::Borrowed(from_path))
  } else {
    let current_dir = &sys
      .env_current_dir()
      .map_err(|e| RequireErrorKind::UnableToGetCwd(UnableToGetCwdError(e)))?;
    normalize_path(Cow::Owned(current_dir.join(from)))
  };

  if cfg!(windows) {
    // return root node_modules when path is 'D:\\'.
    let from_str = from.to_str().unwrap();
    if from_str.len() >= 3 {
      let bytes = from_str.as_bytes();
      if bytes[from_str.len() - 1] == b'\\' && bytes[from_str.len() - 2] == b':'
      {
        let p = format!("{}node_modules", from_str);
        return Ok(vec![p]);
      }
    }
  } else {
    // Return early not only to avoid unnecessary work, but to *avoid* returning
    // an array of two items for a root: [ '//node_modules', '/node_modules' ]
    if from.to_string_lossy() == "/" {
      return Ok(vec!["/node_modules".to_string()]);
    }
  }

  let loader = state.borrow::<NodeRequireLoaderRc>();
  Ok(loader.resolve_require_node_module_paths(&from))
}

#[op2]
#[string]
pub fn op_require_proxy_path(#[string] filename: &str) -> Option<String> {
  // Allow a directory to be passed as the filename
  let trailing_slash = if cfg!(windows) {
    // Node also counts a trailing forward slash as a
    // directory for node on Windows, but not backslashes
    // on non-Windows platforms
    filename.ends_with('\\') || filename.ends_with('/')
  } else {
    filename.ends_with('/')
  };

  if trailing_slash {
    let p = Path::new(filename);
    Some(p.join("noop.js").to_string_lossy().into_owned())
  } else {
    None // filename as-is
  }
}

#[op2(fast)]
pub fn op_require_is_request_relative(#[string] request: &str) -> bool {
  if request.starts_with("./")
    || request.starts_with("../")
    || request == "."
    || request == ".."
  {
    return true;
  }

  if cfg!(windows) {
    if request.starts_with(".\\") {
      return true;
    }

    if request.starts_with("..\\") {
      return true;
    }
  }

  false
}

#[op2]
#[string]
pub fn op_require_resolve_deno_dir<
  TInNpmPackageChecker: InNpmPackageChecker + 'static,
  TNpmPackageFolderResolver: NpmPackageFolderResolver + 'static,
  TSys: ExtNodeSys + 'static,
>(
  state: &mut OpState,
  #[string] request: &str,
  #[string] parent_filename: &str,
) -> Result<Option<String>, deno_path_util::PathToUrlError> {
  let resolver = state.borrow::<NodeResolverRc<
    TInNpmPackageChecker,
    TNpmPackageFolderResolver,
    TSys,
  >>();

  let path = Path::new(parent_filename);
  if let Ok(folder) = resolver.resolve_package_folder_from_package(
    request,
    &UrlOrPathRef::from_path(path),
  ) {
    return Ok(Some(folder.to_string_lossy().into_owned()));
  }

  // Referrer-based resolution failed. When the referrer lives outside the
  // global cache (e.g. a user's project file invoking `require()` through
  // a hook installed by a package that *is* in the cache, mirroring the
  // Playwright config-transpile flow), the npm resolver has no way to
  // anchor the lookup. Fall back to resolving the bare specifier as a
  // top-level dependency in the npm graph.
  let referrer_is_in_npm_package = url_from_file_path(path)
    .map(|url| resolver.in_npm_package(&url))
    .unwrap_or(false);
  if referrer_is_in_npm_package {
    return Ok(None);
  }
  let package_name = bare_specifier_package_name(request);
  if package_name.is_empty() {
    return Ok(None);
  }
  let loader = state.borrow::<NodeRequireLoaderRc>();
  Ok(
    loader
      .resolve_package_folder_from_name(package_name)
      .map(|p| p.to_string_lossy().into_owned()),
  )
}

/// Returns the npm package name portion of a bare specifier such as
/// `pkg`, `pkg/sub`, `@scope/pkg`, or `@scope/pkg/sub`. Returns an empty
/// string for relative or otherwise invalid specifiers.
fn bare_specifier_package_name(specifier: &str) -> &str {
  if specifier.is_empty()
    || specifier.starts_with('.')
    || specifier.starts_with('/')
    || specifier.starts_with('#')
  {
    return "";
  }
  if let Some(rest) = specifier.strip_prefix('@') {
    let Some(scope_end) = rest.find('/') else {
      return "";
    };
    let after_scope = &rest[scope_end + 1..];
    match after_scope.find('/') {
      Some(rel) => &specifier[..1 + scope_end + 1 + rel],
      None => specifier,
    }
  } else {
    match specifier.find('/') {
      Some(i) => &specifier[..i],
      None => specifier,
    }
  }
}

#[op2(fast)]
pub fn op_require_is_deno_dir_package<
  TInNpmPackageChecker: InNpmPackageChecker + 'static,
  TNpmPackageFolderResolver: NpmPackageFolderResolver + 'static,
  TSys: ExtNodeSys + 'static,
>(
  state: &mut OpState,
  #[string] path: &str,
) -> bool {
  let resolver = state.borrow::<NodeResolverRc<
    TInNpmPackageChecker,
    TNpmPackageFolderResolver,
    TSys,
  >>();
  match deno_path_util::url_from_file_path(Path::new(path)) {
    Ok(specifier) => resolver.in_npm_package(&specifier),
    Err(_) => false,
  }
}

#[op2]
pub fn op_require_resolve_lookup_paths(
  #[string] request: &str,
  #[scoped] maybe_parent_paths: Option<Vec<String>>,
  #[string] parent_filename: &str,
) -> Option<Vec<String>> {
  if !request.starts_with('.')
    || (request.len() > 1
      && !request.starts_with("..")
      && !request.starts_with("./")
      && (!cfg!(windows) || !request.starts_with(".\\")))
  {
    let module_paths = vec![];
    let mut paths = module_paths;
    if let Some(mut parent_paths) = maybe_parent_paths
      && !parent_paths.is_empty()
    {
      paths.append(&mut parent_paths);
    }

    if !paths.is_empty() {
      return Some(paths);
    } else {
      return None;
    }
  }

  // In REPL, parent.filename is null/empty.
  if parent_filename.is_empty() {
    // If parent has paths (e.g. fakeParent from require.resolve with
    // options.paths), use those. Otherwise fall back to cwd.
    if let Some(parent_paths) = maybe_parent_paths
      && !parent_paths.is_empty()
    {
      return Some(parent_paths);
    }
    return Some(vec![".".to_string()]);
  }

  let p = Path::new(parent_filename);
  Some(vec![p.parent().unwrap().to_string_lossy().into_owned()])
}

#[op2(fast)]
pub fn op_require_path_is_absolute(#[string] p: &str) -> bool {
  Path::new(p).is_absolute()
}

#[op2(fast, stack_trace)]
pub fn op_require_stat<TSys: ExtNodeSys + 'static>(
  state: &mut OpState,
  #[string] path: &str,
) -> Result<i32, JsErrorBox> {
  let path = Cow::Borrowed(Path::new(path));
  let path = if path.ends_with("node_modules") {
    // skip stat permission checks for node_modules directories
    // because they're noisy and it's fine
    path
  } else {
    ensure_read_permission(state, path)?
  };
  let sys = state.borrow::<TSys>();
  if let Ok(metadata) = sys.fs_metadata(&path) {
    if metadata.file_type().is_file() {
      return Ok(0);
    } else {
      return Ok(1);
    }
  }

  Ok(-1)
}

#[op2(stack_trace)]
#[string]
pub fn op_require_real_path<TSys: ExtNodeSys + 'static>(
  state: &mut OpState,
  #[string] request: &str,
) -> Result<String, RequireError> {
  let path = Cow::Borrowed(Path::new(request));
  let path = ensure_read_permission(state, path)
    .map_err(RequireErrorKind::Permission)?;
  let sys = state.borrow::<TSys>();
  let canonicalized_path =
    deno_path_util::strip_unc_prefix(match sys.fs_canonicalize(&path) {
      Ok(path) => path,
      Err(err) => {
        if path.ends_with("$deno$eval.cjs")
          || path.ends_with("$deno$eval.cts")
          || path.ends_with("$deno$stdin.cjs")
          || path.ends_with("$deno$stdin.cts")
        {
          path.to_path_buf()
        } else {
          return Err(RequireErrorKind::Io(err).into_box());
        }
      }
    });
  Ok(canonicalized_path.to_string_lossy().into_owned())
}

fn path_resolve<'a>(mut parts: impl Iterator<Item = &'a str>) -> PathBuf {
  let mut p = PathBuf::from(parts.next().unwrap());
  for part in parts {
    p = p.join(part);
  }
  normalize_path(Cow::Owned(p)).into_owned()
}

#[op2]
#[string]
pub fn op_require_path_resolve(#[scoped] parts: Vec<String>) -> String {
  path_resolve(parts.iter().map(|s| s.as_str()))
    .to_string_lossy()
    .into_owned()
}

#[op2]
#[string]
pub fn op_require_path_dirname(
  #[string] request: &str,
) -> Result<String, JsErrorBox> {
  let p = Path::new(request);
  if let Some(parent) = p.parent() {
    Ok(parent.to_string_lossy().into_owned())
  } else {
    Err(JsErrorBox::generic("Path doesn't have a parent"))
  }
}

#[op2]
#[string]
pub fn op_require_path_basename(
  #[string] request: &str,
) -> Result<String, JsErrorBox> {
  let p = Path::new(request);
  if let Some(path) = p.file_name() {
    Ok(path.to_string_lossy().into_owned())
  } else {
    Err(JsErrorBox::generic("Path doesn't have a file name"))
  }
}

#[op2(stack_trace)]
#[string]
pub fn op_require_try_self<
  TInNpmPackageChecker: InNpmPackageChecker + 'static,
  TNpmPackageFolderResolver: NpmPackageFolderResolver + 'static,
  TSys: ExtNodeSys + 'static,
>(
  state: &mut OpState,
  #[string] parent_path: &str,
  #[string] request: &str,
  #[serde] conditions: Option<Vec<String>>,
) -> Result<Option<String>, RequireError> {
  let pkg_json_resolver = state.borrow::<PackageJsonResolverRc<TSys>>();
  let pkg = pkg_json_resolver
    .get_closest_package_json(Path::new(parent_path))
    .ok()
    .flatten();
  let Some(pkg) = pkg else {
    return Ok(None);
  };

  if pkg.exports.is_none() {
    return Ok(None);
  }
  let Some(pkg_name) = &pkg.name else {
    return Ok(None);
  };

  let expansion = if request == pkg_name {
    Cow::Borrowed(".")
  } else if let Some(slash_with_export) = request
    .strip_prefix(pkg_name)
    .filter(|t| t.starts_with('/'))
  {
    Cow::Owned(format!(".{}", slash_with_export))
  } else {
    return Ok(None);
  };

  if let Some(exports) = &pkg.exports {
    let node_resolver = state.borrow::<NodeResolverRc<
      TInNpmPackageChecker,
      TNpmPackageFolderResolver,
      TSys,
    >>();
    let referrer = UrlOrPathRef::from_path(&pkg.path);
    // invalidate the resolution cache in case things have changed
    NodeResolutionThreadLocalCache::clear();
    let hook_conditions = js_conditions_to_cow(conditions);
    let conditions = hook_conditions
      .as_deref()
      .unwrap_or_else(|| node_resolver.require_conditions());
    let r = node_resolver.package_exports_resolve(
      &pkg.path,
      &expansion,
      exports,
      Some(&referrer),
      ResolutionMode::Require,
      conditions,
      NodeResolutionKind::Execution,
    )?;
    Ok(Some(url_or_path_to_string(r)?))
  } else {
    Ok(None)
  }
}

#[op2(stack_trace)]
pub fn op_require_read_file<TSys: ExtNodeSys + 'static>(
  state: &mut OpState,
  #[string] file_path_str: &str,
) -> Result<FastString, RequireError> {
  let file_path = Cow::Borrowed(Path::new(file_path_str));
  // todo(dsherret): there's multiple borrows to NodeRequireLoaderRc here
  let file_path = ensure_read_permission(state, file_path)
    .map_err(RequireErrorKind::Permission)?;
  let code = {
    let loader = state.borrow::<NodeRequireLoaderRc>();
    loader
      .load_text_file_lossy(&file_path)
      .map_err(|e| RequireErrorKind::ReadModule(e).into_box())?
  };
  // Apply load-time security mitigations for known React Server Components
  // CVEs to required (CommonJS) source. Opt in via `DENO_PATCH_REACT_CVE`.
  let sys = state.borrow::<TSys>();
  if deno_resolver::is_react_cve_patch_enabled(sys) {
    match deno_resolver::patch_react_cves(file_path_str, code.as_str().into()) {
      Cow::Borrowed(_) => Ok(code),
      Cow::Owned(s) => Ok(s.into()),
    }
  } else {
    Ok(code)
  }
}

#[op2]
#[string]
pub fn op_require_as_file_path(#[string] file_or_url: &str) -> Option<String> {
  #[allow(
    clippy::disallowed_methods,
    reason = "don't need error and this doesn't need to work in Wasm"
  )]
  if let Ok(url) = Url::parse(file_or_url)
    && let Ok(p) = url.to_file_path()
  {
    return Some(p.to_string_lossy().into_owned());
  }

  None // use original input
}

#[op2(stack_trace)]
#[string]
pub fn op_require_resolve_exports<
  TInNpmPackageChecker: InNpmPackageChecker + 'static,
  TNpmPackageFolderResolver: NpmPackageFolderResolver + 'static,
  TSys: ExtNodeSys + 'static,
>(
  state: &mut OpState,
  uses_local_node_modules_dir: bool,
  #[string] modules_path_str: &str,
  #[string] _request: &str,
  #[string] name: &str,
  #[string] expansion: &str,
  #[string] parent_path: &str,
  #[serde] conditions: Option<Vec<String>>,
) -> Result<Option<String>, RequireError> {
  let sys = state.borrow::<TSys>();
  let node_resolver = state.borrow::<NodeResolverRc<
    TInNpmPackageChecker,
    TNpmPackageFolderResolver,
    TSys,
  >>();
  let pkg_json_resolver = state.borrow::<PackageJsonResolverRc<TSys>>();

  let modules_path = Path::new(&modules_path_str);
  let modules_specifier = deno_path_util::url_from_file_path(modules_path)?;
  let is_node_modules_root = modules_path
    .file_name()
    .is_some_and(|name| name == "node_modules");
  let pkg_path = if node_resolver.in_npm_package(&modules_specifier)
    && !uses_local_node_modules_dir
    && !is_node_modules_root
  {
    Cow::Borrowed(modules_path)
  } else {
    let mod_dir = path_resolve([modules_path_str, name].into_iter());
    if sys.fs_is_dir_no_err(&mod_dir) {
      Cow::Owned(mod_dir)
    } else {
      Cow::Borrowed(modules_path)
    }
  };
  let Some(pkg) =
    pkg_json_resolver.load_package_json(&pkg_path.join("package.json"))?
  else {
    return Ok(None);
  };
  let Some(exports) = &pkg.exports else {
    return Ok(None);
  };

  let referrer = if parent_path.is_empty() {
    None
  } else {
    Some(PathBuf::from(parent_path))
  };
  NodeResolutionThreadLocalCache::clear();
  let hook_conditions = js_conditions_to_cow(conditions);
  let conditions = hook_conditions
    .as_deref()
    .unwrap_or_else(|| node_resolver.require_conditions());
  let r = node_resolver.package_exports_resolve(
    &pkg.path,
    &format!(".{expansion}"),
    exports,
    referrer
      .as_ref()
      .map(|r| UrlOrPathRef::from_path(r))
      .as_ref(),
    ResolutionMode::Require,
    conditions,
    NodeResolutionKind::Execution,
  )?;
  Ok(Some(url_or_path_to_string(r)?))
}

deno_error::js_error_wrapper!(
  PackageJsonLoadError,
  JsPackageJsonLoadError,
  "Error"
);

#[op2(fast)]
pub fn op_require_is_maybe_cjs(
  state: &mut OpState,
  #[string] filename: &str,
) -> Result<bool, JsPackageJsonLoadError> {
  let filename = Path::new(filename);
  let Ok(url) = url_from_file_path(filename) else {
    return Ok(false);
  };
  let loader = state.borrow::<NodeRequireLoaderRc>();
  loader.is_maybe_cjs_from_require(&url).map_err(Into::into)
}

#[op2(stack_trace)]
#[serde]
pub fn op_require_read_package_scope<TSys: ExtNodeSys + 'static>(
  state: &mut OpState,
  #[string] package_json_path: &str,
) -> Option<PackageJsonRc> {
  let pkg_json_resolver = state.borrow::<PackageJsonResolverRc<TSys>>();
  let package_json_path = Path::new(package_json_path);
  if package_json_path.file_name() != Some("package.json".as_ref()) {
    // permissions: do not allow reading a non-package.json file
    return None;
  }
  pkg_json_resolver
    .load_package_json(package_json_path)
    .ok()
    .flatten()
}

#[op2(stack_trace)]
#[string]
pub fn op_require_package_imports_resolve<
  TInNpmPackageChecker: InNpmPackageChecker + 'static,
  TNpmPackageFolderResolver: NpmPackageFolderResolver + 'static,
  TSys: ExtNodeSys + 'static,
>(
  state: &mut OpState,
  #[string] referrer_filename: &str,
  #[string] request: &str,
) -> Result<Option<String>, RequireError> {
  let referrer_path = Cow::Borrowed(Path::new(referrer_filename));
  let referrer_path = ensure_read_permission(state, referrer_path)
    .map_err(RequireErrorKind::Permission)?;
  let pkg_json_resolver = state.borrow::<PackageJsonResolverRc<TSys>>();
  let Some(pkg) = pkg_json_resolver.get_closest_package_json(&referrer_path)?
  else {
    return Ok(None);
  };

  if pkg.imports.is_some() {
    let node_resolver = state.borrow::<NodeResolverRc<
      TInNpmPackageChecker,
      TNpmPackageFolderResolver,
      TSys,
    >>();
    NodeResolutionThreadLocalCache::clear();
    let url = node_resolver.resolve_package_import(
      request,
      Some(&UrlOrPathRef::from_path(&referrer_path)),
      Some(&pkg),
      ResolutionMode::Require,
      NodeResolutionKind::Execution,
    )?;
    Ok(Some(url_or_path_to_string(url)?))
  } else {
    Ok(None)
  }
}

#[op2(fast, reentrant)]
pub fn op_require_break_on_next_statement(state: Rc<RefCell<OpState>>) {
  let inspector = { state.borrow().borrow::<Rc<JsRuntimeInspector>>().clone() };
  inspector.wait_for_session_and_break_on_next_statement()
}

#[op2(fast)]
pub fn op_require_can_parse_as_esm(#[string] source: &str) -> bool {
  require_can_parse_as_esm_source(source)
}

fn require_can_parse_as_esm_source(source: &str) -> bool {
  let Ok(specifier) = Url::parse("file:///require-esm-syntax-probe.js") else {
    return false;
  };
  deno_ast::parse_program(ParseParams {
    specifier,
    text: source.to_owned().into(),
    media_type: MediaType::JavaScript,
    capture_tokens: false,
    scope_analysis: false,
    maybe_syntax: None,
  })
  .is_ok_and(|parsed| !parsed.compute_is_script())
}

#[op2]
#[string]
pub fn op_require_trace_dynamic_imports(
  #[string] parent_url: &str,
  #[string] source: &str,
) -> Option<String> {
  trace_dynamic_imports_source(parent_url, source)
}

fn trace_dynamic_imports_source(
  parent_url: &str,
  source: &str,
) -> Option<String> {
  if !source.contains("import") {
    return None;
  }

  let Ok(specifier) = Url::parse(parent_url) else {
    return None;
  };
  let parsed = deno_ast::parse_program(ParseParams {
    specifier: specifier.clone(),
    text: source.to_owned().into(),
    media_type: MediaType::JavaScript,
    capture_tokens: false,
    scope_analysis: false,
    maybe_syntax: None,
  })
  .ok()?;
  let mut program = (*parsed.program()).clone();
  let mut rewriter = DynamicImportTracingRewriter {
    parent_url: parent_url.to_string(),
    rewritten: false,
  };
  program.visit_mut_with(&mut rewriter);
  if !rewriter.rewritten {
    return None;
  }

  let source_map = SourceMap::single(specifier, source.to_string());
  let program_ref = match &program {
    Program::Module(module) => ProgramRef::Module(module),
    Program::Script(script) => ProgramRef::Script(script),
  };
  deno_ast::emit(
    program_ref,
    &NoopComments,
    &source_map,
    &EmitOptions {
      source_map: SourceMapOption::None,
      ..Default::default()
    },
  )
  .ok()
  .map(|emitted| emitted.text)
}

struct DynamicImportTracingRewriter {
  parent_url: String,
  rewritten: bool,
}

impl VisitMut for DynamicImportTracingRewriter {
  fn visit_mut_call_expr(&mut self, call: &mut CallExpr) {
    call.visit_mut_children_with(self);

    let import_token = match &call.callee {
      Callee::Import(import_token) => *import_token,
      _ => return,
    };
    let original_args = std::mem::take(&mut call.args);
    let loader = dynamic_import_loader(import_token, original_args.len());

    let mut traced_args = Vec::with_capacity(original_args.len() + 2);
    traced_args.push(string_arg(&self.parent_url));
    traced_args.push(expr_arg(loader));
    traced_args.extend(original_args);

    call.callee =
      Callee::Expr(Box::new(global_helper_expr("__denoNodeTraceModuleImport")));
    call.args = traced_args;
    call.type_args = None;
    self.rewritten = true;
  }
}

fn dynamic_import_loader(import_token: Import, arg_count: usize) -> Expr {
  let identifiers: Vec<Ident> = (0..arg_count)
    .map(|index| {
      Ident::new_no_ctxt(format!("__denoNodeImportArg{index}").into(), DUMMY_SP)
    })
    .collect();
  let params = identifiers
    .iter()
    .cloned()
    .map(|id| Pat::Ident(BindingIdent { id, type_ann: None }))
    .collect();
  let import_args = identifiers
    .into_iter()
    .map(|id| expr_arg(Expr::Ident(id)))
    .collect();
  Expr::Arrow(ArrowExpr {
    span: DUMMY_SP,
    ctxt: SyntaxContext::empty(),
    params,
    body: Box::new(BlockStmtOrExpr::Expr(Box::new(Expr::Call(CallExpr {
      span: DUMMY_SP,
      ctxt: SyntaxContext::empty(),
      callee: Callee::Import(import_token),
      args: import_args,
      type_args: None,
    })))),
    is_async: false,
    is_generator: false,
    type_params: None,
    return_type: None,
  })
}

fn global_helper_expr(name: &str) -> Expr {
  Expr::Member(MemberExpr {
    span: DUMMY_SP,
    obj: Box::new(Expr::Ident(Ident::new_no_ctxt(
      "globalThis".into(),
      DUMMY_SP,
    ))),
    prop: MemberProp::Ident(IdentName::new(name.into(), DUMMY_SP)),
  })
}

fn string_arg(value: &str) -> ExprOrSpread {
  expr_arg(Expr::Lit(Lit::Str(Str {
    span: DUMMY_SP,
    value: value.into(),
    raw: None,
  })))
}

fn expr_arg(expr: Expr) -> ExprOrSpread {
  ExprOrSpread {
    spread: None,
    expr: Box::new(expr),
  }
}

fn url_or_path_to_string(
  url: UrlOrPath,
) -> Result<String, deno_path_util::UrlToFilePathError> {
  if url.is_file() {
    Ok(url.into_path()?.to_string_lossy().into_owned())
  } else {
    Ok(url.to_string_lossy().into_owned())
  }
}

#[cfg(test)]
mod tests {
  use super::require_can_parse_as_esm_source;
  use super::trace_dynamic_imports_source;

  #[test]
  fn require_esm_probe_ignores_dynamic_import_expression() {
    assert!(!require_can_parse_as_esm_source(
      r#"const mod = import("node:fs"); module.exports = mod;"#,
    ));
  }

  #[test]
  fn require_esm_probe_detects_static_module_syntax() {
    assert!(require_can_parse_as_esm_source(
      r#"import fs from "node:fs"; export default fs;"#,
    ));
  }

  #[test]
  fn dynamic_import_trace_rewrite_wraps_import_expression() {
    let rewritten = trace_dynamic_imports_source(
      "file:///app/mod.cjs",
      r#"const result = import("node:http");"#,
    )
    .expect("dynamic import should rewrite");

    assert!(
      rewritten.contains(
        r#"globalThis.__denoNodeTraceModuleImport("file:///app/mod.cjs""#
      ),
      "rewritten source should call the tracing helper: {rewritten}"
    );
    assert!(
      rewritten.contains("import(__denoNodeImportArg0)"),
      "rewritten source should preserve a real dynamic import in the loader callback: {rewritten}"
    );
    assert!(
      rewritten.contains("\"node:http\""),
      "rewritten source should preserve the original specifier: {rewritten}"
    );
  }

  #[test]
  fn dynamic_import_trace_rewrite_leaves_unrelated_source_untouched() {
    assert_eq!(
      trace_dynamic_imports_source(
        "file:///app/mod.cjs",
        r#"module.exports = require("node:fs");"#,
      ),
      None
    );
  }
}
