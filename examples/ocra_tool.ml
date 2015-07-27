open Sexplib
open Sexplib.Conv

type t = {
  s: Rfc6287.t;
  k: Cstruct.t;
  c: int64 option ;
  p: Cstruct.t option ;
  cw: int option ;
  tw: int option ;
}

let hex_string cs = let `Hex s = Hex.of_cstruct cs in  s

let sexp_of_t t =
  let hex_string_o = function
    | None -> None
    | Some cs -> Some (hex_string cs) in
  let record kvs =
    Sexp.List List.(map (fun (k, v) -> (Sexp.List [Sexp.Atom k; v])) kvs) in
  record [
    "s", sexp_of_string (Rfc6287.string_of_t t.s);
    "k", sexp_of_string (hex_string t.k);
    "c", sexp_of_option sexp_of_int64 t.c;
    "p", sexp_of_option sexp_of_string (hex_string_o t.p);
    "cw", sexp_of_option sexp_of_int t.cw;
    "tw", sexp_of_option sexp_of_int t.tw; ]

let t_of_sexp = function
  | Sexp.List l ->
    (match
       List.fold_left (fun (s,k,c,p,cw,tw) -> function
           | Sexp.List [ Sexp.Atom "s"; v ] ->
             let open Rresult in
             let suite = match Rfc6287.t_of_string (string_of_sexp v) with
               | Error _ -> failwith "broken credentials file"
               | Ok x -> x in
             (Some suite,k,c,p,cw,tw)
           | Sexp.List [ Sexp.Atom "k"; v ] ->
             let key = Nocrypto.Uncommon.Cs.of_hex (string_of_sexp v) in
             (s, Some key,c,p,cw,tw)
           | Sexp.List [ Sexp.Atom "c"; v ] ->
             let counter = option_of_sexp int64_of_sexp v in
             (s,k,counter,p,cw,tw)
           | Sexp.List [ Sexp.Atom "p"; v ] ->
             let pin = match option_of_sexp string_of_sexp v with
               | None -> None
               | Some x -> Some (Nocrypto.Uncommon.Cs.of_hex x) in
             (s,k,c, pin,cw,tw)
           | Sexp.List [ Sexp.Atom "cw"; v ] ->
             let counter_window = option_of_sexp int_of_sexp v in
             (s,k,c,p, counter_window,tw)
           | Sexp.List [ Sexp.Atom "tw"; v ] ->
             let timestamp_window = option_of_sexp int_of_sexp v in
             (s,k,c,p,cw, timestamp_window)
           | _ -> failwith "broken credentials file")
         (None,None,None,None,None,None) l with
    | (Some s, Some k, c, p, cw, tw) -> {s;k;c;p;cw;tw}
    | _ -> failwith "broken credentials file")
  | _ -> failwith "broken credentials file"

let of_file f =
  try
    let stat = Unix.stat f in
    let buf = Bytes.create (stat.Unix.st_size) in
    let fd = Unix.openfile f [Unix.O_RDONLY] 0 in
    let _read_b = Unix.read fd buf 0 stat.Unix.st_size in
    let () = Unix.close fd in
    t_of_sexp (Sexp.of_string buf)
  with | Unix.Unix_error (e, _, _) -> failwith (Unix.error_message e)

let file_of f t =
  try
    let fd = Unix.openfile f [Unix.O_WRONLY; Unix.O_CREAT] 0o600 in
    let s = Sexp.to_string_hum (sexp_of_t t) in
    let _written_bytes = Unix.single_write fd s 0 (Bytes.length s) in
    let () = Unix.close fd in
    `Ok ()
  with | Unix.Unix_error (e, _, _) -> failwith (Unix.error_message e)

let p_f = function
  | None -> failwith "credential_file required"
  | Some x -> x

let initx cred_file i_s i_k i_c i_p i_cw i_tw =
  let open Rfc6287 in
  let open Rresult in
  let e s = failwith s in
  try
    let s = match i_s with
      |None -> failwith "suite_string required"
      |Some x -> match t_of_string x with
        | Error _ -> failwith "invalid suite"
        | Ok y -> y in
    let k = match i_k with
      | None -> e "key required"
      | Some x ->
        let y = match Stringext.chop_prefix ~prefix:"0x" x with
          |None -> x
          |Some z -> z in
        try Nocrypto.Uncommon.Cs.of_hex y with
        | Invalid_argument _ -> e "invalid key" in
    let di = di_of_t s in
    let _ = match di.s with
      | None -> ()
      | Some _ -> e "suite requires unsupported session parameter (S)" in
    let c = match (di.c, i_c) with
      | (false, None) -> None
      | (false, Some _) ->
        e "suite does not require counter parameter: -c <...> must not be set"
      | (true, None) ->
        e "suite requires counter parameter: -c <...> missing"
      | (true, Some x) -> Some x in
    let p = match (di.p, i_p) with
      | (None, None) -> None
      | (Some _, None) ->
        e "suite requires pin parameter: -p <...> missing"
      | (None, Some _) ->
        e "suite does not require pin parameter: -p <...> must not be set"
      | (Some dgst, Some x) ->
        Some (Nocrypto.Hash.digest dgst (Cstruct.of_string x)) in
    let cw = match (di.c, i_cw) with
      | (_, None) -> None
      | (true, Some x) when x > 0 -> Some x
      | (true, Some _) -> e "invalid counter_window value"
      | (false, Some x) ->
        e "suite does not require counter parameter: -w <...> must not be set" in
    let tw = match (di.t, i_tw) with
      | (_, None) -> None
      | (Some _, Some x) -> Some x
      | (None, Some _) ->
        e "suite does not require timestamp parameter: -t <...> must not be set" in
    file_of (p_f cred_file) {s;k;c;p;cw;tw}
  with | Failure f -> `Error (false, f)

let infox cred_file =
  let print_t t =
    Printf.eprintf "suite:            %s\n" (Rfc6287.string_of_t t.s);
    Printf.eprintf "key:              0x%s\n" (hex_string t.k);
    (match t.c with
     | None -> ()
     | Some c -> Printf.eprintf "counter:          0x%Lx\n" c);
    (match t.p with
     | None -> ()
     | Some p -> Printf.eprintf "pinhash:          0x%s\n" (hex_string p));
    (match t.cw with
     | None -> ()
     | Some cw -> Printf.eprintf "counter_window:   %d\n" cw);
    (match t.tw with
     | None -> ()
     | Some cw -> Printf.eprintf "timestamp_window: %d\n" cw); `Ok () in
  try print_t (of_file (p_f cred_file)) with | Failure e -> `Error (false, e)

let challengex cred_file =
  let () = Nocrypto_entropy_unix.initialize () in
  try
    let t = of_file (p_f cred_file) in
    let _ = Printf.eprintf "%s\n" (Rfc6287.challenge t.s) in `Ok ()
  with | Failure e -> `Error (false, e)

let vr_aux cred_file i_q =
  let p_q = function
    | None -> failwith "challenge required"
    | Some x -> x in
  let q = p_q i_q in
  let f = p_f cred_file in
  let t = of_file f in
  let suite = t.s in
  let p = match t.p with
    | None -> None
    | Some x -> Some (`Digest x) in
  let di = Rfc6287.di_of_t suite in
  let ts = match di.Rfc6287.t with
    | None -> None
    | Some _ -> Some `Now in
  q,f,t,suite,p,ts,None,t.c,t.k

let verifyx cred_file i_q i_a =
  try
    let a = match i_a with
      | None -> failwith "response required"
      | Some x -> Cstruct.of_string x in
    let q,f,t,suite,p,ts,s,c,key = vr_aux cred_file i_q in
    let cw,tw = t.cw,t.tw in
    let open Rresult in
    let open Rfc6287 in
    match Rfc6287.verify1 ~c ~p ~s ~t:ts ~cw ~tw ~key ~q ~a suite with
    | Ok (true, next) -> let _ = Printf.eprintf "success\n" in
      (match next with
       | None -> `Ok ()
       | Some newc -> file_of f {t with c = (Some newc)})
    | Ok (false, None) -> let _ = Printf.eprintf "failure\n" in `Ok ()
    | Error Window s -> failwith s
    | Error DataInput s -> failwith s
    | _ -> failwith "do not know"
  with | Failure e -> `Error (false, e)

let responsex cred_file i_q =
  try
    let q,f,t,suite,p,ts,s,c,key = vr_aux cred_file i_q in
    let open Rresult in
    let open Rfc6287 in
    match Rfc6287.gen1 ~c ~p ~s ~t:ts ~key ~q suite with
    | Ok x ->
      let _ = Printf.eprintf "%s\n" (Cstruct.to_string x) in
      (match t.c with
       | None -> `Ok ()
       | Some x -> file_of f {t with c = (Some (Int64.add x 1L))})
    | Error DataInput e -> failwith e
    | _ -> failwith "do not know"
  with | Failure e -> `Error (false, e)

open Cmdliner

let copts_sect = "COMMON OPTIONS"
let help_secs = [
  `S copts_sect;
  `P "These options are common to all commands.";
  `S "MORE HELP";
  `P "Use `$(mname) $(i,COMMAND) --help' for help on a single command.";
  `S "BUGS"; `P "sure."]

let cred_file =
  let docs = copts_sect in
  let doc = "the OCRA credential file." in
  Arg.(value & opt (some string) None & info ["f"] ~docv:"credential_file"
         ~doc ~docs)

let init_cmd =
  let s =
    let doc = "OCRA suite string." in
    Arg.(value & opt (some string) None & info ["s"]
           ~docv:"suite_string" ~doc) in
  let k =
    let doc = "specified as hexadecimal string." in
    Arg.(value & opt (some string) None & info ["k"] ~docv:"key" ~doc) in
  let c =
    let doc = "If the suite_string requires a counter parameter,
      $(docv) is the initial counter value." in
    Arg.(value & opt (some int64) None & info ["c"] ~docv:"counter" ~doc) in
  let p =
    let doc = "If the suite_string requires a pin-hash parameter, it is
      calculated from $(docv) using the pin-hash algorith in suite-string" in
    Arg.(value & opt (some string) None & info ["p"] ~docv:"pin" ~doc) in
  let cw =
    let doc = "If the suite_string requires a counter parameter,
      $(docv) specifies the maximum number of verify attempts
      (incrementing the counter value). This parameter is optional" in
    Arg.(value & opt (some int) None & info ["w"] ~docv:"counter_window" ~doc) in
  let tw =
    let doc = "If the suite_string requires a timestamp parameter,
      $(docv) specifies the number of timestamp steps will be made while
      verifying a response. The verify process will start at (now() -
      $(docv)) and end at (now() + $(docv)).
      This parameter is optional." in
    Arg.(value & opt (some int) None & info ["t"] ~docv:"timestamp_window"
           ~doc) in
  let doc = "Initialize OCRA credential file." in
  let man = [
    `S "DESCRIPTION";
    `P "Parse suite string; serialise key, additional DataInput and verify
    options to credential file ..."] @ help_secs
  in
  Term.(ret (pure initx $ cred_file $ s $ k $ c $ p $ cw $ tw)),
  Term.info "init" ~sdocs:copts_sect ~doc ~man

let info_cmd =
  let doc = "Show content of OCRA credential file." in
  let man =
    [`S "DESCRIPTION";
     `P "Show suite string, key, additional DataInput and verify
     options in credential file ..."] @ help_secs in
  Term.(ret (pure infox $ cred_file)), Term.info "info" ~doc
    ~sdocs:copts_sect ~man

let challenge_cmd =
  let doc = "Generate OCRA challenge" in
  let man =
    [ `S "Description";
      `P "Generate OCRA challenge according to the challenge format specified in
      the credential file ..."] @ help_secs in
  Term.(ret (pure challengex $ cred_file)), Term.info "challenge"
    ~doc ~sdocs:copts_sect ~man

let verify_cmd =
  let q =
    Arg.(value & opt (some string) None & info ["q"] ~docv:"challenge") in
  let a =
    Arg.(value & opt (some string) None & info ["a"] ~docv:"response") in
  let doc = "Verify ORCA response" in
  let man =
    [ `S "Description";
      `P "Verify ORCA response with challenge and credentials from
      credential file.";
      `P "Successfull verification will write the next valid counter to the
      credential file if the OCRA suite specifies C."] @ help_secs in
  Term.(ret (pure verifyx $ cred_file $ q $ a)),
  Term.info "verify" ~doc ~sdocs:copts_sect ~man

let response_cmd =
  let q =
    Arg.(value & opt (some string) None & info ["q"] ~docv:"challenge") in
  let doc = "Generate OCRA response" in
  let man =
    [ `S "Description";
      `P "Calculate OCRA response to challenge";
      `P "If OCAR suite specifies C, teh counter in the credential_file will be
          incremented."] @ help_secs in
  Term.(ret (pure responsex $ cred_file $ q)), Term.info "response"
    ~doc ~sdocs:copts_sect ~man

let default_cmd =
  let doc = "create and view OCRA credential files" in
  let man = help_secs in
  Term.(ret (pure (fun _ -> `Help (`Pager, None)) $ cred_file)),
  Term.info "ocra_tool" ~sdocs:copts_sect ~doc ~man

let cmds = [init_cmd; info_cmd; challenge_cmd; verify_cmd; response_cmd]

let () = match Term.eval_choice ~catch:false default_cmd cmds with
  | `Error _ -> exit 1 | _ -> exit 0
