const e = new Error("rejected");
e.code = "EREJ";
Promise.reject(e);
