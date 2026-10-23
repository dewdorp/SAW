import { useMe } from "../../App";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Page } from "./types";
export function usePages<T>(path:string,key:unknown[]) {
 const me=useMe();
 const [cursor,setCursor]=useState("");
 const q=useQuery({queryKey:[...key,cursor,me.data?.id,me.data?.permissions],queryFn:()=>api.get<Page<T>>(`${path}${path.includes("?")?"&":"?"}limit=50${cursor ? "&cursor="+encodeURIComponent(cursor):""}`)});
 return {...q,next:()=>setCursor(q.data?.next_cursor || ""),first:()=>setCursor(""),cursor};
}
