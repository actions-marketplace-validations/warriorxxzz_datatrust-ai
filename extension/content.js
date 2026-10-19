let typingTimer;
const doneTypingInterval = 800; 
let warningBox = null;


function createWarningBox() {
    if (warningBox) return;
    warningBox = document.createElement("div");
    warningBox.id = "datatrust-warning";
    warningBox.innerHTML = `
        <h3>⚠️ Personal Info Detected</h3>
        <p id="datatrust-msg"></p>
    `;
    document.body.appendChild(warningBox);
}


document.addEventListener("input", (e) => {
    const el = e.target;
    
    if (!el.matches("textarea, [contenteditable='true']")) return;

    clearTimeout(typingTimer);
    
    typingTimer = setTimeout(async () => {
        const text = el.value || el.innerText;
        if (!text || text.length < 5) {
            if (warningBox) warningBox.style.display = "none";
            return;
        }

        try {
            
            const res = await fetch("http://127.0.0.1:8765/scan", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ text })
            });
            const data = await res.json();

            if (data.risk === "HIGH" || data.risk === "MEDIUM") {
                createWarningBox();
                const types = [...new Set(data.findings.map(f => f.type.replace("NP_", "").replace("_", " ")))].join(", ");
                document.getElementById("datatrust-msg").innerText = `We found: ${types}. Please remove this before sending.`;
                warningBox.style.display = "block";
            } else {
                if (warningBox) warningBox.style.display = "none";
            }
        } catch (error) {
            console.log("DataTrust AI: Server offline");
        }
    }, doneTypingInterval);
});
