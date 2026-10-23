import { Reasons } from "./labels";
export function ReleasePreview({value}:{value:any}) {
 return <div className="col"><b>실제 파일 미리보기</b><div className="small">파일 SHA256 {value.artifact_sha256}</div>
 <div className="small">{value.validation?.passed?"파일 검증 통과":"파일 검증 미통과"}</div>
 {(value.validation?.checks||[]).map((v:any,i:number)=><div className="small" key={i}>{v.code} · {v.state} · {v.detail}</div>)}
 {(value.samples||[]).map((v:any)=><div key={v.path}><b className="small">{v.path}</b><pre style={{whiteSpace:"pre-wrap",overflowWrap:"anywhere"}}>{v.content_text}</pre><span className="small">{v.preview_bytes}/{v.bytes_total} bytes{v.truncated?" · 일부만 표시":""}</span></div>)}
 <div className="small">생략 파일 {value.omitted?.files||0}개 · 생략 {value.omitted?.bytes||0} bytes</div><Reasons value={value.limits}/></div>;
}
