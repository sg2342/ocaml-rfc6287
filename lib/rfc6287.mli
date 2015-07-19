(** RFC6287 (OCRA) *)

(** The abstract OCRA (suite) type *)
type t

val t_of_string : string -> t option

val string_of_t : t -> string

val challenge : t -> string

type timestamp = [`Now | `Int64 of int64 ]

val gen: ?c:int64 -> ?p:Cstruct.t -> ?s:Cstruct.t -> ?t:timestamp -> suite:t -> key:Cstruct.t -> string -> Cstruct.t

val verify: ?c:int64 -> ?p:Cstruct.t -> ?s:Cstruct.t -> ?t:timestamp -> ?cw:int -> ?tw:int -> suite:t -> key:Cstruct.t -> string -> Cstruct.t -> bool * int64 option
