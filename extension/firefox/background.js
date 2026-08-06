chrome.webNavigation.onBeforeNavigate.addListener(
async function(details){

let url = details.url;

// ignore internal pages
if(
url.startsWith("chrome://") ||
url.startsWith("chrome-extension://") ||
url.includes("127.0.0.1")
){
return;
}


// ----------------------
// LAYER 1: FAST CHECK
// ----------------------

let lower = url.toLowerCase();

let dangerousExt = [
".exe",".zip",".rar",".apk",".bat",".msi"
];

for(let ext of dangerousExt){

if(lower.endsWith(ext)){

console.log("CyberGuard FAST BLOCK:",url);

chrome.tabs.update(details.tabId,{
url: chrome.runtime.getURL("block.html")
});

return;

}

}


// ----------------------
// LAYER 2: AI BACKEND
// ----------------------

try{

let response = await fetch("http://127.0.0.1:5000/scan",{

method:"POST",

headers:{
"Content-Type":"application/json"
},

body:JSON.stringify({url:url})

});

let data = await response.json();

console.log("CyberGuard AI result:",data);

if(data.result === "PHISHING"){

console.log("CyberGuard AI BLOCK:",url);

chrome.tabs.update(details.tabId,{
url: chrome.runtime.getURL("block.html")
});

}

}catch(e){

console.log("CyberGuard backend error:",e);

}

}
);