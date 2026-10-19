let typingTimer;
const doneTypingInterval = 800; // 0.8 seconds
let warningBox = null;
let lastScannedText = "";

function createWarningBox() {
    if (warningBox) return;
    
    warningBox = document.createElement("div");
    warningBox.id = "datatrust-warning";
    
    warningBox.innerHTML = `
        <div class="dt-header">
            <div class="dt-header-left">
                <span>🛑</span>
                <span>Privacy Alert</span>
            </div>
            <button class="dt-close" id="dt-close-btn">&times;</button>
        </div>
        <div class="dt-body">
            <p>We detected sensitive information in your message:</p>
            <ul class="dt-list" id="dt-list"></ul>
            <p class="dt-footer">Please remove these details before sending to protect your privacy.</p>
        </div>
    `;
    document.body.appendChild(warningBox);

    document.getElementById("dt-close-btn").addEventListener("click", () => {
        warningBox.style.display = "none";
    });
}

document.addEventListener("input", (e) => {
    const el = e.target;
    if (!el.matches("textarea, [contenteditable='true']")) return;

    clearTimeout(typingTimer);
    
    typingTimer = setTimeout(async () => {
        const text = el.value || el.innerText;
        
        if (!text || text.length < 5) {
            if (warningBox) warningBox.style.display = "none";
            lastScannedText = "";
            return;
        }
        if (text === lastScannedText) return;
        
        lastScannedText = text;

        try {
            const res = await fetch("http://127.0.0.1:8765/scan", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ text })
            });
            const data = await res.json();

            if (data.risk === "HIGH" || data.risk === "MEDIUM") {
                createWarningBox();
                
                const listElement = document.getElementById("dt-list");
                listElement.innerHTML = ""; 
                
                const uniqueTypes = [...new Set(data.findings.map(f => f.type.replace("NP_", "").replace("IN_", "").replace(/_/g, " ")))];
                
                uniqueTypes.forEach(type => {
                    const li = document.createElement("li");
                    li.innerText = type;
                    listElement.appendChild(li);
                });

                warningBox.style.display = "block";
            } else {
                if (warningBox) warningBox.style.display = "none";
            }
        } catch (error) {
            console.log("DataTrust AI: Server offline or unreachable.");
        }
    }, doneTypingInterval);
});
