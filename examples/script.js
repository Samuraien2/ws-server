function getWebSocketURL() {
  const urlParams = new URLSearchParams(window.location.search);
  return "ws://" + (urlParams.get("ws") || "localhost:9001");
}

document.title = "WebSocket";

const ws = new WebSocket(getWebSocketURL());
ws.onopen = () => {
  console.log("Connected");
  const data = new Uint8Array([10, 20, 30, 40, 50]);
  ws.send(data);
};

ws.onclose = () => {
  console.log("Closed");
};

ws.onerror = () => {
  console.log("Error");
};

ws.binaryType = "arraybuffer";

ws.onmessage = (ev) => {
  if (ev.data instanceof ArrayBuffer) {
    const view = new Uint8Array(ev.data);
    console.log("Received:", view);
  }
};
