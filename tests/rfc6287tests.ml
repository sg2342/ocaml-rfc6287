(* test vectors from "Appendix C. Test Vectors" of OCRA RFC *)

open OUnit2

let key k =
  let s = match k with
    | `K20 -> "3132333435363738393031323334353637383930"
    | `K32 -> "313233343536373839303132333435363738393031323" ^
              "3343536373839303132"
    | `K64 -> "313233343536373839303132333435363738393031323" ^
              "334353637383930313233343536373839303132333435" ^
              "36373839303132333435363738393031323334" in
  Hex.to_cstruct (`Hex s)

let pinhash =
  Some (Nocrypto.Hash.SHA1.digest (Cstruct.of_string "1234"))

let timestamp =
  Some 0x132d0b6L

let suite ctx =
  let open OUnitTest in
  Rfc6287.t_of_string (string_of_node (List.hd ctx.path))

let istr l i =
  let c = char_of_int (i + (int_of_char '0')) in
  String.make l c

let o1 ctx =
  let ocra =
    Rfc6287.gen
      ~c:None ~p:None ~s:None ~t:None
      ~suite:(suite ctx) ~key:(key `K20) in
  let l = ["237653"; "243178"; "653583"; "740991"; "608993"; "388898";
           "816933"; "224598"; "750600"; "294470"] in
  List.iteri (fun i r ->
      let q = istr 8 i in
      let x = Cstruct.to_string(ocra ~q:q) in
      assert_equal r x) l

let o2 ctx =
  let ocra =
    Rfc6287.gen
      ~s:None ~t:None
      ~p:pinhash ~suite:(suite ctx) ~key:(key `K32) ~q:"12345678" in
  let l = ["65347737"; "86775851"; "78192410"; "71565254"; "10104329";
           "65983500"; "70069104"; "91771096"; "75011558"; "08522129"] in
  List.iteri (fun i r ->
      let c = Some (Int64.of_int i) in
      let x = Cstruct.to_string(ocra ~c:c) in
      assert_equal r x) l

let o3 ctx =
  let ocra =
    Rfc6287.gen
      ~c:None ~s:None ~t:None
      ~p:pinhash ~suite:(suite ctx) ~key:(key `K32) in
  let l = ["83238735"; "01501458"; "17957585"; "86776967"; "86807031"] in
  List.iteri (fun i r ->
      let q = istr 8 i in
      let x = Cstruct.to_string(ocra ~q:q) in
      assert_equal r x) l

let o4 ctx =
  let ocra =
    Rfc6287.gen
      ~p:None ~s:None ~t:None
      ~suite:(suite ctx) ~key:(key `K64) in
  let l = ["07016083"; "63947962"; "70123924"; "25341727"; "33203315";
           "34205738"; "44343969"; "51946085"; "20403879"; "31409299"] in
  List.iteri (fun i r ->
      let c = Some (Int64.of_int i) in
      let q = istr 8 i in
      let x = Cstruct.to_string(ocra ~q:q ~c:c) in
      assert_equal r x) l

let o5 ctx =
  let ocra =
    Rfc6287.gen
      ~p:None ~c:None ~s:None
      ~t:timestamp ~suite:(suite ctx) ~key:(key `K64) in
  let l =["95209754"; "55907591"; "22048402"; "24218844"; "36209546"] in
  List.iteri (fun i r ->
      let q = istr 8 i in
      let x = Cstruct.to_string(ocra ~q:q) in
      assert_equal r x) l

let s1 ctx =
  let ocra =
    Rfc6287.gen
      ~p:None ~c:None ~s:None ~t:None
      ~suite:(suite ctx) ~key:(key `K32) in
  let l = [("SIG10000","53095496");
           ("SIG11000","04110475");
           ("SIG12000","31331128");
           ("SIG13000","76028668");
	   ("SIG14000","46554205")] in
  List.iter (fun (q, r) ->
      let x = Cstruct.to_string(ocra ~q:q) in
      assert_equal r x) l

let s2 ctx =
  let ocra =
    Rfc6287.gen
      ~p:None ~c:None ~s:None
      ~t:timestamp ~suite:(suite ctx) ~key:(key `K64) in
  let l = [("SIG1000000","77537423");
           ("SIG1100000","31970405");
           ("SIG1200000","10235557");
	   ("SIG1300000","95213541");
           ("SIG1400000","65360607")] in
  List.iter (fun (q, r) ->
      let x = Cstruct.to_string(ocra ~q:q) in
      assert_equal r x) l

let m1 ctx =
  let ocra =
    Rfc6287.gen
      ~p:None ~c:None ~s:None ~t:None
      ~suite:(suite ctx) ~key:(key `K32) in
  let l = [("CLI22220SRV11110","28247970");
           ("CLI22221SRV11111","01984843");
	   ("CLI22222SRV11112","65387857");
           ("CLI22223SRV11113","03351211");
	   ("CLI22224SRV11114","83412541");
           ("SRV11110CLI22220","15510767");
           ("SRV11111CLI22221","90175646");
           ("SRV11112CLI22222","33777207");
           ("SRV11113CLI22223","95285278");
           ("SRV11114CLI22224","28934924")] in
  List.iter (fun (q, r) ->
      let x = Cstruct.to_string(ocra ~q:q) in
      assert_equal r x) l

let m2 ctx =
  let ocra =
    Rfc6287.gen
      ~p:None ~c:None ~s:None ~t:None
      ~suite:(suite ctx) ~key:(key `K64) in
  let l = [("CLI22220SRV11110","79496648");
           ("CLI22221SRV11111","76831980");
           ("CLI22222SRV11112","12250499");
           ("CLI22223SRV11113","90856481");
           ("CLI22224SRV11114","12761449")] in
  List.iter (fun (q, r) ->
      let x = Cstruct.to_string(ocra ~q:q) in
      assert_equal r x) l

let m3 ctx =
  let ocra =
    Rfc6287.gen
      ~c:None ~s:None ~t:None
      ~p:pinhash ~suite:(suite ctx) ~key:(key `K64) in
  let l = [("SRV11110CLI22220","18806276");
	   ("SRV11111CLI22221","70020315");
	   ("SRV11112CLI22222","01600026");
	   ("SRV11113CLI22223","18951020");
	   ("SRV11114CLI22224","32528969")] in
  List.iter (fun (q, r) ->
      let x = Cstruct.to_string(ocra ~q:q) in
      assert_equal r x) l

let suite =
  "All" >::: ["one_way" >::: ["OCRA-1:HOTP-SHA1-6:QN08" >::o1;
                              "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1" >:: o2;
                              "OCRA-1:HOTP-SHA256-8:QN08-PSHA1" >:: o3;
                              "OCRA-1:HOTP-SHA512-8:C-QN08" >:: o4;
                              "OCRA-1:HOTP-SHA512-8:QN08-T1M" >:: o5;];
              "signature" >::: ["OCRA-1:HOTP-SHA256-8:QA08" >::s1;
                                "OCRA-1:HOTP-SHA512-8:QA10-T1M" >:: s2];
              "mutual" >::: ["OCRA-1:HOTP-SHA256-8:QA08" >:: m1;
                             "OCRA-1:HOTP-SHA512-8:QA08" >:: m2;
                             "OCRA-1:HOTP-SHA512-8:QA08-PSHA1" >:: m3];
             ]

