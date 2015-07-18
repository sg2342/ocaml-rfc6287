(** RFC6287 (OCRA) *)

(** The abstract OCRA (suite) type *)
type t

val t_of_string : string -> t option

val string_of_t : t -> string

val challenge : t -> string

val gen: ?c:int64 -> ?p:Cstruct.t -> ?s:Cstruct.t -> ?t:int64 -> suite:t -> key:Cstruct.t -> string -> Cstruct.t
