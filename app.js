/* UI, diagrams and interactive experiments for Control Theory Lecture Two. */
(function(){
"use strict";
const $=id=>document.getElementById(id);
const lessons=window.LESSONS||[];
const LSKEY="control-lecture-two-progress-v1";
let selected=0,step=0,showAll=false,selectedAnswer=-1,finished=new Set();
try{finished=new Set(JSON.parse(localStorage.getItem(LSKEY)||"[]"))}catch(_){}
const fmt=n=>n.toFixed(2).replace(/\.?0+$/,"");
const svgTag=(d,cl="wire")=>'<path class="'+cl+'" d="'+d+'"/>';
const txt=(x,y,v,cl="")=>'<text x="'+x+'" y="'+y+'" text-anchor="middle" class="'+cl+'">'+v+'</text>';
const dot=(x,y)=>'<circle cx="'+x+'" cy="'+y+'" r="4" fill="#1d463b"/>';
const resistor=(x1,x2,y,t)=>svgTag('M'+(x1-15)+' '+y+' H'+x1,'wire')+svgTag('M'+x1+' '+y+' l10 -11 l14 22 l14 -22 l14 22 l14 -22 l14 22 l10 -11','part')+svgTag('M'+(x1+90)+' '+y+' H'+x2)+txt((x1+x2)/2,y-24,t);
const coil=(x1,x2,y,t)=>svgTag('M'+(x1-12)+' '+y+' H'+x1)+Array.from({length:4},(_,i)=>svgTag('M'+(x1+20*i)+' '+y+' a10 13 0 1 1 20 0','part')).join('')+svgTag('M'+(x1+80)+' '+y+' H'+x2)+txt((x1+x2)/2,y-22,t);
const capV=(x,top,bottom,t)=>svgTag('M'+x+' '+top+' V145 M'+x+' 157 V'+bottom)+svgTag('M'+(x-18)+' 145 h36 M'+(x-18)+' 157 h36','part')+txt(x+35,155,t);
const capH=(x1,x2,y,t)=>svgTag('M'+x1+' '+y+' H'+(x1+30)+' M'+(x1+44)+' '+y+' H'+x2)+svgTag('M'+(x1+30)+' '+(y-16)+' v32 M'+(x1+44)+' '+(y-16)+' v32','part')+txt((x1+x2)/2,y-26,t);
const resV=(x,top,bottom,t)=>svgTag('M'+x+' '+top+' V'+(top+12))+svgTag('M'+x+' '+(top+12)+' l-10 9 l20 11 l-20 11 l20 11 l-20 11 l10 10','part')+svgTag('M'+x+' '+(top+75)+' V'+bottom)+txt(x+35,top+43,t);
const damperH=(x1,x2,y,t)=>svgTag('M'+x1+' '+y+' h18 M'+(x1+18)+' '+(y-14)+' v28 M'+(x1+18)+' '+(y-14)+' h36 v28 h-36 M'+(x1+18)+' '+y+' h58 M'+(x1+76)+' '+y+' H'+x2,'part')+txt((x1+x2)/2,y+29,t);
const springH=(x1,x2,y,t)=>svgTag('M'+x1+' '+y+' h9 l7 -12 l13 24 l13 -24 l13 24 l13 -24 l13 24 l8 -12 H'+x2,'part')+txt((x1+x2)/2,y-24,t);
const source=()=>'<circle cx="35" cy="136" r="24" stroke="#1d463b" stroke-width="2.2" fill="#e8f2ec"/>'+txt(35,131,'+')+txt(35,150,'−')+svgTag('M35 72 V112 M35 160 V228');
const input=(label="Eᵢ")=>txt(16,188,label);
const output=(at=485,label="Eₒ")=>txt(at+44,97,label,'out');
const base=(inside)=>'<svg viewBox="0 0 620 260" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="رسم توضيحي لمسار مكونات النظام">'+inside+'</svg>';
function diagram(kind){
 let b="";
 if(kind==="rlc"){
  b=source()+svgTag('M35 72 H99')+coil(110,224,72,"L")+resistor(250,366,72,"R")+svgTag('M366 72 H486 V106')+svgTag('M486 106 V145 M486 157 V228 H35')+svgTag('M468 145 h36 M468 157 h36','part')+txt(531,156,"C")+txt(566,94,"Eₒ",'out')+svgTag('M486 72 H555 M486 228 H555')+input()+dot(486,72);
 }else if(kind==="rc-ladder"){
  b=source()+svgTag('M35 72 H85')+resistor(106,216,72,"R₁")+svgTag('M216 72 H280 V110')+resistor(330,430,72,"R₂")+svgTag('M280 72 H310 M430 72 H490 V145 M490 157 V228 H35 M280 157 V228')+capV(280,110,228,"C₁")+svgTag('M472 145 h36 M472 157 h36','part')+dot(280,72)+dot(490,72)+input()+svgTag('M490 72 H557 M490 228 H557')+txt(568,91,"Eₒ",'out')+txt(535,158,"C₂");
 }else if(kind==="rlc-ladder"){
  b=source()+svgTag('M35 72 H85')+resistor(106,214,72,"R₁")+svgTag('M214 72 H279 V115')+coil(0,0,0,"").replace(/[\s\S]*/,"");
  // Shared vertical coil shown as four windings on the vertical branch.
  b+=Array.from({length:4},(_,i)=>'<path class="part" d="M279 '+(115+18*i)+' c-17 0 -17 18 0 18"/>').join('')+svgTag('M279 187 V228')+txt(307,156,"L")+svgTag('M279 72 H314')+resistor(335,434,72,"R₂")+svgTag('M434 72 H490 V145 M490 157 V228 H35 M279 228 H490')+svgTag('M472 145 h36 M472 157 h36','part')+txt(534,158,"C")+dot(279,72)+dot(490,72)+input()+svgTag('M490 72 H555 M490 228 H555')+txt(566,94,"Eₒ",'out');
 }else if(kind==="rc-mixed"||kind==="hw-rc"){
  b=source()+svgTag('M35 72 H97 V37 H129')+resistor(147,254,37,"R₂")+svgTag('M254 37 H346 V72 H552')+svgTag('M97 72 V110 H151')+capH(151,257,110,"C₂")+svgTag('M257 110 H346 V72')+dot(97,72)+dot(346,72)+resV(346,79,156,"R₁")+svgTag('M346 156 V180')+svgTag('M328 180 h36 M328 191 h36','part')+svgTag('M346 191 V228 H35')+txt(384,191,"C₁")+input();
  if(kind==="hw-rc"){b+=svgTag('M346 171 H549 M346 228 H549')+txt(560,194,"Eₒ",'out')}else{b+=svgTag('M346 72 H552 M346 228 H552')+txt(567,92,"Eₒ",'out')}
 }else if(kind==="hw-inductors"){
  b=source()+svgTag('M35 72 H89')+coil(105,206,72,"L₁")+svgTag('M206 72 H270 V94')+coil(334,435,72,"L₂")+svgTag('M270 72 H316 M435 72 H490 V145 M490 157 V228 H35')+resV(270,95,228,"R")+svgTag('M472 145 h36 M472 157 h36','part')+txt(531,155,"C")+dot(270,72)+svgTag('M321 45 V30 H440 V45','flow')+txt(324,21,"+ Vₒ −",'out')+input("Vᵢ");
  // Fix coil output voltage ends correspond to the two ends of L₂.
 }else if(kind==="mass-single"||kind==="mass-two"||kind==="mass-two-simple"||kind==="train"){
  const two=kind!=="mass-single";
  b=svgTag("M32 222 H592","ground");
  if(!two){
   b+=svgTag('M38 48 V218 M42 48 V218')+springH(42,283,92,"k")+svgTag('M42 175 H91')+damperH(91,270,175,"fᵥ")+svgTag('M270 175 H284');
   b+='<rect class="fillmass" x="284" y="70" width="125" height="125" rx="9"/>'+txt(346,133,"M")+svgTag('M410 131 H540','active')+svgTag('M530 122 l10 9 -10 9','active')+txt(480,112,"F(t)")+txt(349,56,"x(t) →");
  }else{
   b+='<rect class="fillmass" x="70" y="76" width="125" height="121" rx="8"/>'+txt(132,137,kind==="mass-two-simple"?"1 kg":kind==="train"?"m₂":"M₂")+'<rect class="fillmass" x="416" y="76" width="125" height="121" rx="8"/>'+txt(478,137,kind==="mass-two-simple"?"1 kg":kind==="train"?"m₁":"M₁");
   b+=springH(195,416,105,kind==="mass-two-simple"?"k=1":kind==="train"?"k":"k₂")+damperH(195,416,165,kind==="mass-two-simple"?"b=1":kind==="train"?"b":"fᵥ₃");
   b+=svgTag('M542 118 H595','active')+svgTag('M587 110 l8 8 -8 8','active')+txt(568,103,"F(t)")+txt(133,64,kind==="train"?"x₂": "x₂")+txt(476,64,"x₁");
   if(kind==="mass-two"){b+=txt(132,213,"k₃ , fᵥ₂")+txt(480,213,"k₁ , fᵥ₁")}if(kind==="train"){b+=txt(132,213,"c₂")+txt(480,213,"c₁")}
  }
 }else if(kind==="suspension"){
  b=svgTag('M70 223 H546','ground')+svgTag('M310 198 V223')+'<rect class="fillmass" x="228" y="42" width="164" height="54" rx="9"/>'+txt(310,75,"m")+txt(419,70,"xₒ →")+svgTag('M250 96 V116')+springH(0,0,0,"").replace(/[\s\S]*/,"");
  b+=svgTag('M250 116 l-10 8 l20 10 l-20 10 l20 10 l-20 10 l10 8 V196','part')+damperH(310,350,144,"b")+svgTag('M350 144 V193 M250 196 H351')+txt(211,148,"k")+svgTag('M305 200 V222','active')+txt(401,218,"xᵢ →")+svgTag('M310 222 v-21');
 }else if(kind==="spring-net"){
  b=svgTag('M150 25 H430 M150 232 H430','wire')+txt(462,31,"xᵢ")+txt(466,124,"xₒ")+txt(466,195,"y");
  b+=svgTag('M265 25 V46')+svgTag('M265 46 l-13 8 l26 11 l-26 11 l26 11 l-13 9 V116','part')+txt(224,70,"k₁");
  b+=svgTag('M341 25 V50')+resV(341,50,116,"b₁");
  b+=svgTag('M235 116 H372 M341 116 V130')+resV(341,130,184,"b₂")+svgTag('M341 184 H265 V196')+svgTag('M265 196 l-12 7 l24 8 l-24 8 l12 7 V232','part')+txt(219,216,"k₂")+svgTag('M372 116 H442 M341 184 H442')+txt(388,106,"xₒ");
 }
 return base(b);
}
function svgNumber(s){return '<span class="math-display">\\('+s+'\\)</span>'}
function typeset(el){if(window.MathJax&&MathJax.typesetPromise){MathJax.typesetClear&&MathJax.typesetClear([el]);MathJax.typesetPromise([el]).catch(()=>{})}}
const makeMath=s=>'<div class="math-display">\\['+s+'\\]</div>';
function save(){try{localStorage.setItem(LSKEY,JSON.stringify([...finished]))}catch(_){}}
function progress(){const n=finished.size;$("doneCount").textContent=n;$("sideProgressText").textContent=n+" من "+lessons.length+" مسائل";$("progressBar").style.width=(n/lessons.length*100)+"%";const r=$("doneButton");if(r){r.textContent=finished.has(lessons[selected].id)?"✓ أنهيت هذه المسألة":"علّم المسألة كمكتملة";r.classList.toggle("light",finished.has(lessons[selected].id))}}
function navBuild(){
 const nav=$("lessonNav");nav.innerHTML="";let last="";
 lessons.forEach((l,i)=>{if(l.section!==last){last=l.section;let h=document.createElement("div");h.className="side-label";h.textContent=last==="electric"?"الدوائر الكهربائية — 6":last==="mechanical"?"الأنظمة الميكانيكية — 5":"الواجبات المحلولة — 5";nav.append(h)}
 let button=document.createElement("button");button.className="nav-link"+(selected===i?" active":"");button.dataset.index=i;
 let name=document.createElement("span");name.textContent=l.title;let tick=document.createElement("span");tick.className="tinycheck";tick.textContent=finished.has(l.id)?"✓":"";
 button.append(name,tick);button.addEventListener("click",()=>pick(i));nav.append(button)})}
function pick(index){
 if(index<0||index>=lessons.length)return; selected=index;step=0;showAll=false;selectedAnswer=-1;
 navBuild();renderLesson();closeMenu();window.scrollTo({top:$("lessonHost").getBoundingClientRect().top+window.scrollY-16,behavior:"smooth"});
}
function stepHTML(s,i){
 return '<article class="step-card"><div class="step-kicker">الخطوة '+(i+1)+'</div><h4>'+s.t+'</h4><div class="step-equation">'+makeMath(s.e)+'</div><p class="step-explain"><strong>من أين جاءت؟</strong> '+s.w+'</p></article>'
}
function renderStep(){
 const l=lessons[selected],host=$("stepsHost");
 if(showAll){host.innerHTML='<div class="all-steps">'+l.steps.map(stepHTML).join("</div><div style='height:10px'></div><div>")+'</div>';}
 else host.innerHTML=stepHTML(l.steps[step],step);
 $("stepNumber").textContent=(showAll?"الكل":(step+1)+" / "+l.steps.length);
 $("stepProgress").style.width=(showAll?100:(step+1)/l.steps.length*100)+"%";
 $("prevStep").disabled=showAll||step===0;$("nextStep").disabled=showAll||step>=l.steps.length-1;
 $("nextStep").textContent=step===l.steps.length-2?"اعرض النتيجة ←":"الخطوة التالية ←";
 $("allSteps").textContent=showAll?"عرض خطوة واحدة":"عرض الحل كاملاً";
 $("miniSteps").innerHTML=l.steps.map((_,i)=>'<button aria-label="الخطوة '+(i+1)+'" data-step="'+i+'" class="'+(step===i&&!showAll?"selected":"")+'">'+(i+1)+'</button>').join("");
 $("miniSteps").querySelectorAll("button").forEach(b=>b.onclick=()=>{step=Number(b.dataset.step);showAll=false;renderStep()});
 const visible=showAll||step===l.steps.length-1;$("finalBox").hidden=!visible;
 $("finalMath").innerHTML=makeMath(l.answer);
 typeset($("stepsHost"));if(visible)typeset($("finalMath"));
}
function renderQuiz(){
 const q=lessons[selected].quiz;$("quizQ").textContent=q.q;
 $("quizOptions").innerHTML="";
 q.a.forEach((a,i)=>{let b=document.createElement("button");b.textContent=(i+1)+" — "+a;if(selectedAnswer!==-1&&i===q.c)b.className="good";if(selectedAnswer===i&&i!==q.c)b.className="bad";b.onclick=()=>{selectedAnswer=i;renderQuiz()};$("quizOptions").append(b)});
 $("quizFeedback").textContent=selectedAnswer===-1?"":(selectedAnswer===q.c?"صحيح. ":"راجع الفكرة: ")+q.e;
}
function setLab(l){
 const isRlc=l.visual==="rlc";const isMass=l.visual==="mass-single";$("labPanel").hidden=!(isRlc||isMass);if(!isRlc&&!isMass)return;
 $("labTitle").textContent=isRlc?"تجربة مباشرة: استجابة دائرة RLC":"تجربة مباشرة: كيف تتحرك الكتلة؟";
 const cfg=isRlc?[["L","المحاثة L","H",.4,4,1.2,.1],["R","المقاومة R","Ω",.5,8,2,.1],["C","السعة C","F",.3,3,1,.1]]:[["M","الكتلة M","kg",.4,4,1.5,.1],["b","معامل التخميد b","N·s/m",.3,8,1.3,.1],["k","ثابت النابض k","N/m",.4,6,2,.1]];
 $("labInputs").innerHTML="";
 cfg.forEach(([id,label,unit,min,max,v,incr])=>{const d=document.createElement("div");d.className="slidebox";d.innerHTML='<label for="l-'+id+'">'+label+' <output id="o-'+id+'">'+v+' '+unit+'</output></label><input id="l-'+id+'" type="range" min="'+min+'" max="'+max+'" step="'+incr+'" value="'+v+'">';$("labInputs").append(d)});
 function draw(){
 const data={};cfg.forEach(([id,_,unit])=>{data[id]=Number($("l-"+id).value);$("o-"+id).textContent=fmt(data[id])+" "+unit});
 const A=isRlc?data.L*data.C:data.M, B=isRlc?data.R*data.C:data.b, K=isRlc?1:data.k;
 const zeta=B/(2*Math.sqrt(A*K)),dt=.01,count=1200,points=[];
 let y=0,v=0;
 function f(q,w){return [w,(1-B*w-K*q)/A]}
 for(let i=0;i<=count;i++){
  if(i%5===0)points.push([i*dt,y]); const a=f(y,v),b=f(y+a[0]*dt/2,v+a[1]*dt/2),c=f(y+b[0]*dt/2,v+b[1]*dt/2),d=f(y+c[0]*dt,v+c[1]*dt);y+=dt*(a[0]+2*b[0]+2*c[0]+d[0])/6;v+=dt*(a[1]+2*b[1]+2*c[1]+d[1])/6;
 }
 const steady=1/K,maxVal=Math.max(...points.map(x=>x[1]),steady*1.1,1),minVal=Math.min(0,...points.map(x=>x[1]));
 let path="";points.forEach(([t,q],i)=>{const xx=34+t/12*480;const yy=204-(q-minVal)/(maxVal-minVal)*174;path+=(i?" L":"M")+xx.toFixed(2)+" "+yy.toFixed(2)});
 const eqY=204-(steady-minVal)/(maxVal-minVal)*174;
 $("labGraph").innerHTML='<svg viewBox="0 0 535 228" role="img" aria-label="رسم بياني لاستجابة الخرج بعد تطبيق دخل ثابت"><path d="M34 20 V204 H519" fill="none" stroke="#9cafaa" stroke-width="1.6"/><path d="M34 '+eqY+' H519" fill="none" stroke="#b5c6ba" stroke-width="1.5" stroke-dasharray="5 5"/><path d="'+path+'" fill="none" stroke="#14806c" stroke-width="3" stroke-linejoin="round"/><text x="38" y="15" font-size="11" fill="#466a60">الاستجابة</text><text x="510" y="221" font-size="11" fill="#466a60" text-anchor="end">الزمن 12s</text><text x="42" y="'+(eqY-8)+'" font-size="11" fill="#8b744f">القيمة المستقرة</text></svg>';
 $("labSummary").textContent=(zeta<.99?"تخميد منخفض: قد تتجاوز الاستجابة قيمتها النهائية أو تتذبذب.":zeta>1.01?"تخميد مرتفع: الاستجابة تميل لأن تكون أبطأ دون تذبذب.":"تخميد حرج تقريباً: حد الانتقال بين الحالتين.")+" معامل التخميد النسبي ζ ≈ "+fmt(zeta)+". غيّر القيم وقارن المنحنى.";
 }
 cfg.forEach(([id])=>$("l-"+id).addEventListener("input",draw));draw();
}
function renderLesson(){
 const l=lessons[selected];document.title=l.title+" | دراسة السيطرة";
 $("currentCategory").textContent=l.section==="electric"?"الدوائر الكهربائية":l.section==="mechanical"?"الأنظمة الميكانيكية":"حلول الواجب";
 $("lessonTitle").textContent=l.title;
 $("pageNum").textContent="PDF ص "+l.page;
 $("goalMath").innerHTML=makeMath(l.goal);
 $("lessonLead").textContent=l.lead;
 $("diagram").innerHTML=diagram(l.visual);
 $("diagramCaption").textContent=l.lead;
 $("warn").hidden=!l.notice;$("warn").textContent=l.notice;
 $("stepCount").textContent=l.steps.length+" خطوات";
 $("lastButton").disabled=selected>=lessons.length-1;
 $("firstButton").disabled=selected===0;
 $("lastButton").textContent=selected>=lessons.length-1?"وصلت إلى آخر مسألة":"المسألة التالية ←";
 $("firstButton").textContent="→ المسألة السابقة";
 renderStep();renderQuiz();setLab(l);progress();typeset($("goalMath"));
}
function initLaw(){
 const names={r:["المقاومة — قانون أوم","V_R=Ri","كلما زاد التيار عند مقاومة ثابتة، زاد هبوط الجهد."],c:["المتسعة — تراكم الشحنة","i_C=C\\frac{dv_C}{dt}","التيار يساوي معدل تراكم الشحنة؛ جهد المتسعة يرتفع مع تراكمها."],l:["المحث — تغير التيار","v_L=L\\frac{di_L}{dt}","إذا لم يتغيّر التيار في محث مثالي، فالجهد عليه صفر."]};
 let mode="r";
 const slider=$("lawSlider");
 function law(){
  $("lawName").textContent=names[mode][0];$("lawFormula").innerHTML=makeMath(names[mode][1]);$("lawExplanation").textContent=names[mode][2];
  const val=Number(slider.value);$("lawSlideLabel").textContent=mode==="r"?"التيار i = "+fmt(val)+" A":mode==="c"?"معدل تغيّر الجهد = "+fmt(val)+" V/s":"معدل تغيّر التيار = "+fmt(val)+" A/s";
  $("lawResult").textContent=(mode==="r"?"عند R = 4 Ω، فإن الجهد = ":mode==="c"?"عند C = 2 F، فإن التيار = ":"عند L = 3 H، فإن الجهد = ")+fmt(val*(mode==="r"?4:mode==="c"?2:3))+(mode==="c"?" A":" V");
  document.querySelectorAll("[data-law]").forEach(b=>b.classList.toggle("primary",b.dataset.law===mode));typeset($("lawFormula"));
 }
 document.querySelectorAll("[data-law]").forEach(b=>b.onclick=()=>{mode=b.dataset.law;law()});
 slider.addEventListener("input",law);law();
}
function closeMenu(){$("sidebar").classList.remove("open");$("backdrop").classList.remove("visible")}
function ready(){
 navBuild();renderLesson();initLaw();
 $("nextStep").onclick=()=>{if(step<lessons[selected].steps.length-1){step++;renderStep()}};
 $("prevStep").onclick=()=>{if(step>0){step--;renderStep()}};
 $("allSteps").onclick=()=>{showAll=!showAll;renderStep()};
 $("lastButton").onclick=()=>pick(selected+1);
 $("firstButton").onclick=()=>pick(selected-1);
 $("doneButton").onclick=()=>{const id=lessons[selected].id;if(finished.has(id))finished.delete(id);else finished.add(id);save();navBuild();progress()};
 $("searchLessons").oninput=function(){let term=this.value.trim().toLowerCase();$("lessonNav").querySelectorAll(".nav-link").forEach(b=>b.hidden=!b.textContent.toLowerCase().includes(term));$("lessonNav").querySelectorAll(".side-label").forEach(h=>h.hidden=!!term)};
 $("menuBtn").onclick=()=>{$("sidebar").classList.add("open");$("backdrop").classList.add("visible")};
 $("backdrop").onclick=closeMenu;
 $("sizeBtn").onclick=()=>document.body.classList.toggle("large-text");
 document.addEventListener("keydown",e=>{if(e.target.matches("input,textarea"))return;if(e.key==="Escape")closeMenu();if(e.key==="ArrowLeft")$("nextStep").click();if(e.key==="ArrowRight")$("prevStep").click()});
}
if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",ready);else ready();
})();