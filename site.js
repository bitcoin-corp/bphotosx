/* bPhotosX page motion: bmoviesx.com's cover-flow, rails, reveal and dock (2 Nov 2026), without the hero film and
   sound control. The cover-flow is built from the example photo cards, so the photos and credits live in one place. */
(function(){
  var rm=matchMedia('(prefers-reduced-motion: reduce)').matches;
  function esc(s){return String(s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}

  // Cover-flow (same behaviour as bMoviesX / bVideoX / bMusicX)
  (function(){
    var src=document.querySelectorAll('#photos a.card');if(!src.length)return;
    var items=[].slice.call(src).slice(0,16).map(function(a){return{h:a.href,img:a.querySelector('img').getAttribute('src'),t:a.querySelector('b').textContent}});
    var cf=document.getElementById('cf'),dots=document.getElementById('cfDots'),cur=0,dragged=false;
    cf.innerHTML=items.map(function(v,i){return '<figure class="cf-card" data-i="'+i+'"><img src="'+esc(v.img)+'" alt="Example photo by '+esc(v.t)+'" loading="'+(i<4||i>items.length-3?'eager':'lazy')+'" decoding="async" draggable="false"><figcaption class="cap"><b>'+esc(v.t)+'</b><a href="'+esc(v.h)+'" target="_blank" rel="noopener">Photo on Unsplash &rarr;</a></figcaption></figure>'}).join('');
    dots.innerHTML=items.map(function(v){return '<button type="button" aria-label="Photo by '+esc(v.t)+'"></button>'}).join('');
    var cards=[].slice.call(cf.children);
    function layout(){var n=cards.length,w=cards[0].offsetWidth;cards.forEach(function(c,i){var d=i-cur;if(d>n/2)d-=n;if(d<-n/2)d+=n;var a=Math.abs(d);
      c.style.transform='translate(-50%,-50%) translateX('+(d*w*.62)+'px) translateZ('+(-a*160)+'px) rotateY('+(-Math.sign(d)*Math.min(a,1)*38)+'deg)';
      c.style.opacity=a>3?0:1-a*.2;c.style.zIndex=100-a;c.style.filter=a?'brightness(.5)':'none';c.style.pointerEvents=a>3?'none':'auto';
      c.classList.toggle('on',a===0);c.setAttribute('aria-hidden',a===0?'false':'true');
      var l=c.querySelector('a');if(a===0)l.removeAttribute('tabindex');else l.setAttribute('tabindex','-1')});
      [].forEach.call(dots.children,function(b,i){b.setAttribute('aria-current',i===cur?'true':'false')})}
    function go(i){cur=(i+cards.length)%cards.length;layout()}
    document.getElementById('cfPrev').onclick=function(){go(cur-1)};document.getElementById('cfNext').onclick=function(){go(cur+1)};
    [].forEach.call(dots.children,function(b,i){b.onclick=function(){go(i)}});
    cf.addEventListener('click',function(e){if(dragged){dragged=false;e.preventDefault();return}var c=e.target.closest('.cf-card');if(c&&+c.dataset.i!==cur){e.preventDefault();go(+c.dataset.i)}});
    cf.addEventListener('keydown',function(e){if(e.key==='ArrowLeft')go(cur-1);if(e.key==='ArrowRight')go(cur+1)});
    // Trackpad / Magic Mouse: horizontal wheel steps one card per gesture; vertical scroll untouched
    var acc=0,steps=0,idle=0;
    cf.addEventListener('wheel',function(e){var k=e.deltaMode===1?16:e.deltaMode===2?400:1,dx=e.deltaX*k,dy=e.deltaY*k;if(e.shiftKey&&!dx){dx=dy;dy=0}
      if(Math.abs(dx)<=Math.abs(dy)||Math.abs(dx)<2)return;e.preventDefault();clearTimeout(idle);idle=setTimeout(function(){acc=0;steps=0},200);acc+=dx;
      if(steps===0&&Math.abs(acc)>=50){go(cur+Math.sign(acc));steps=1;acc=0}else if(steps===1&&Math.abs(acc)>=600){go(cur+Math.sign(acc));steps=2}},{passive:false});
    // drag / touch swipe
    var sx=null,sy=0;
    cf.addEventListener('pointerdown',function(e){sx=e.clientX;sy=e.clientY;dragged=false});
    cf.addEventListener('pointermove',function(e){if(sx!=null&&Math.abs(e.clientX-sx)>8&&Math.abs(e.clientX-sx)>Math.abs(e.clientY-sy))dragged=true});
    cf.addEventListener('pointerup',function(e){if(sx==null)return;var dx=e.clientX-sx;if(dragged&&Math.abs(dx)>40)go(cur+(dx<0?1:-1));sx=null});
    cf.addEventListener('pointercancel',function(){sx=null});
    cf.addEventListener('dragstart',function(e){e.preventDefault()});
    addEventListener('resize',layout);layout();
  })();

  if(!rm){
    document.documentElement.classList.add('js');
    // headings: light sweep once on reveal
    document.querySelectorAll('.head h2,.cta h2').forEach(function(h){new IntersectionObserver(function(e,o){if(e[0].isIntersecting){h.classList.add('sw');o.disconnect()}},{threshold:.6}).observe(h)});
    // count-up for step numbers
    document.querySelectorAll('.steps .n').forEach(function(n){var to=+n.textContent;new IntersectionObserver(function(e,o){if(!e[0].isIntersecting)return;o.disconnect();var t0=performance.now();(function f(t){var k=Math.min(1,(t-t0)/700);n.textContent=Math.max(1,Math.round(to*k));if(k<1)requestAnimationFrame(f)})(t0)},{threshold:.6}).observe(n)});
    if(matchMedia('(hover:hover) and (pointer:fine)').matches){
      // photo tilt + glare
      document.querySelectorAll('.card .p').forEach(function(p){p.addEventListener('pointermove',function(e){var r=p.getBoundingClientRect(),x=(e.clientX-r.left)/r.width,y=(e.clientY-r.top)/r.height;p.style.setProperty('--ry',((x-.5)*14).toFixed(1)+'deg');p.style.setProperty('--rx',((.5-y)*14).toFixed(1)+'deg');p.style.setProperty('--gx',(130-x*160)+'%')});p.addEventListener('pointerleave',function(){p.style.setProperty('--rx','0deg');p.style.setProperty('--ry','0deg')})});
    }
    var rv=document.querySelectorAll('.rv');
    if('IntersectionObserver' in window){var io=new IntersectionObserver(function(es){es.forEach(function(e){if(e.isIntersecting){e.target.classList.add('in');io.unobserve(e.target)}})},{rootMargin:'0px 0px -8% 0px',threshold:.01});rv.forEach(function(el){io.observe(el)})}
    else rv.forEach(function(el){el.classList.add('in')});
  }
  if('IntersectionObserver' in window){
    var dock=document.getElementById('dock'),hero=document.getElementById('top');
    new IntersectionObserver(function(e){dock.classList.toggle('on',!e[0].isIntersecting)},{threshold:0,rootMargin:'-120px 0px 0px 0px'}).observe(hero);
  }
  document.querySelectorAll('[data-rail]').forEach(function(w){
    var r=w.querySelector('.rail'),b=w.querySelectorAll('.arrows button');
    function upd(){b[0].disabled=r.scrollLeft<8;b[1].disabled=r.scrollLeft+r.clientWidth>=r.scrollWidth-8}
    b.forEach(function(x){x.addEventListener('click',function(){r.scrollBy({left:x.dataset.dir*r.clientWidth*.8,behavior:rm?'auto':'smooth'})})});
    r.addEventListener('scroll',upd,{passive:true});addEventListener('resize',upd);upd();
  });
})();
