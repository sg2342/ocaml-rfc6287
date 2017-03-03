#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let coverage = Conf.with_pkg ~default:false "coverage"
let examples = Conf.with_pkg ~default:false "examples"

let cmd c os files =
  let build =
    if Conf.value c coverage then
      let coverage_arg = Cmd.(v "-pkg" % "bisect_ppx") in
      let coverage_cmd c os = Cmd.(Pkg.build_cmd c os %% coverage_arg) in
      coverage_cmd
    else
      Pkg.build_cmd
  in
  OS.Cmd.run @@ Cmd.(build c os %% of_list files)

let () =
  let not_rfc6287_deps = Some ["bisect_ppx";"oUnit";"ounit";"cmdliner"] in
  let opams =
    [ Pkg.opam_file "opam" ~lint_deps_excluding:not_rfc6287_deps ]
  in
  Pkg.describe ~build:(Pkg.build ~cmd ()) ~opams "rfc6287" @@ fun c ->
  let examples = Conf.value c examples in
  Ok [
    Pkg.mllib "lib/rfc6287.mllib";
    Pkg.test "test/tests";
    Pkg.bin ~cond:examples "examples/ocra_tool"
  ]
