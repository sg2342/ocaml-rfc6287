#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let () =
  Pkg.describe "rfc6287" @@ fun c ->
  Ok [
    Pkg.mllib "lib/rfc6287.mllib";
    Pkg.test "test/tests";
  ]
