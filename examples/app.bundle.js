// Minified-style frontend bundle excerpt (example artifact for JS ingestion).
const API="/api/v1";
async function getOrder(id){return fetch(`/api/v1/orders/${id}`).then(r=>r.json());}
function applyPromo(c){return axios.post("/internal/api/v1/promo/apply",{code:c});}
function debugPanel(){return fetch("/admin/internal/metrics");}
// stray dev token left in bundle (example only)
const DEV_TOKEN="sk-live-EXAMPLE0000000000000000notreal";
export {getOrder, applyPromo};
