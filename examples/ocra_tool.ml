
let initx cred_file s k c p cw tw =
  `Error (false, "not implemented")

let infox f =
  `Error (false, "not implemented")

open Cmdliner;;

let copts_sect = "COMMON OPTIONS"
let help_secs = [
  `S copts_sect;
  `P "These options are common to all commands.";
  `S "MORE HELP";
  `P "Use `$(mname) $(i,COMMAND) --help' for help on a single command.";`Noblank;
  `S "BUGS"; `P "Check bug reports at http://bugs.example.org.";]

let cred_file =
  let docs = copts_sect in
  let doc = "the OCRA credential file." in
  Arg.(value & opt (some string) None & info ["f"] ~docv:"credential_file"
         ~doc ~docs)

let init_cmd =
  let s =
    let doc = "OCRA suite string." in
    Arg.(value & opt string "OCRA-1:HOTP-SHA1-6:C-QN08-PSHA1" & info ["s"]
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
  Term.(pure initx $ cred_file $ s $ k $ c $ p $ cw $ tw),
  Term.info "init" ~sdocs:copts_sect ~doc ~man

let info_cmd =
  let doc = "Show content of OCRA credential file." in
  let man =
    [`S "DESCRIPTION";
     `P "Show suite string, key, additional DataInput and verify
     options in credential file ..."] @ help_secs in
  Term.(pure infox $ cred_file), Term.info "info" ~doc ~sdocs:copts_sect ~man

let default_cmd =
  let doc = "create and view OCRA credential files" in
  let man = help_secs in
  Term.(ret (pure (fun _ -> `Help (`Pager, None)) $ cred_file)),
  Term.info "ocra_tool" ~sdocs:copts_sect ~doc ~man

let cmds = [init_cmd; info_cmd]

let () = match Term.eval_choice default_cmd cmds with
  | `Error _ -> exit 1 | _ -> exit 0
