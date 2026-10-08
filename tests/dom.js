
const {JSDOM}=require("jsdom");const sid=process.argv[2];
(async()=>{
const dom=await JSDOM.fromURL("http://127.0.0.1:8000/",{runScripts:"dangerously",resources:"usable",pretendToBeVisual:true,beforeParse(w){w.Element.prototype.scrollIntoView=()=>{};w.scrollTo=()=>{};w.fetch=(u,o)=>fetch(new URL(u,"http://127.0.0.1:8000/"),o)}});
const w=dom.window,d=w.document,wait=ms=>new Promise(r=>setTimeout(r,ms)),out=[];
const chk=(n,c)=>out.push((c?"PASS ":"FAIL ")+n);
await wait(1200);chk("scan view renders",!!d.querySelector("#go"));
for(const [tab,probe] of [["","Verify fix by re-scanning"],["/grc","Risk register"],["/governance","on-chain"],["/chat","Ask the audit"],["/report","Verify a report"]]){
 w.location.hash="#/s/"+sid+tab;await wait(900);chk("view "+(tab||"findings")+" renders '"+probe+"'",d.body.textContent.includes(probe)&&!d.body.textContent.includes("Something went wrong"));}
w.location.hash="#/s/"+sid;await wait(900);
chk("exploit steps shown",d.body.textContent.includes("Exploit scenario"));
d.querySelector(".vf").click();await wait(1500);chk("verify-fix result rendered",/Resolved|Not resolved/.test(d.body.textContent));
w.location.hash="#/s/"+sid+"/chat";await wait(800);d.querySelector("#q").value="what first?";d.querySelector("#send").click();await wait(1200);chk("chat reply rendered",d.body.textContent.includes("Fix F1 first"));
w.location.hash="#/history";await wait(800);chk("history lists scan",d.querySelectorAll("tr.link").length>=1);
console.log(out.join("\n"));process.exit(0)})()
