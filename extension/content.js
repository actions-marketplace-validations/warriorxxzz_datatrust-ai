let typingTimer;
const doneTypingInterval = 800;
let warningBox = null;
let lastScannedText = "";

const patterns = {
    "NP_CITIZENSHIP": /\b\d{1,2}[-\/\s]\d{1,2}[-\/\s]\d{2,4}[-\/\s]\d{4,5}\b/g,
    "NP_NID": /\b(?!9[678]\d{8})\d{10}\b/g,
    "NP_PAN": /\b\d{9}\b/g,
    "NP_PASSPORT": /\b(?:[A-Z]\d{7}|[A-Z]{2}\d{6,8})\b/g,
    "NP_PHONE_MOBILE": /\b(?:\+977[- ]?)?9[678]\d{8}\b/g,
    "NP_PHONE_LANDLINE": /\b0[1-9]\d{6,7}\b/g,
    "IN_AADHAAR": /\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b/g,
    "IN_PAN": /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g,
    "IN_IFSC": /\b[A-Z]{4}0[A-Z0-9]{6}\b/g,
    "IN_UPI": /\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}\b/g,
    "IN_PHONE_MOBILE": /\b(?:\+91[\s-]?)?[6-9]\d{9}\b/g,
    "CREDIT_CARD": /\b(?:\d[ -]?){13,19}\b/g,
    "EMAIL": /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    "IPV4": /\b(?:\d{1,3}\.){3}\d{1,3}\b/g
};

const severity = {
    "NP_CITIZENSHIP": "HIGH", "NP_NID": "HIGH", "NP_PAN": "HIGH", "NP_PASSPORT": "HIGH",
    "IN_AADHAAR": "HIGH", "IN_PAN": "HIGH", "CREDIT_CARD": "HIGH",
    "NP_PHONE_MOBILE": "MEDIUM", "IN_UPI": "MEDIUM", "IN_PHONE_MOBILE": "MEDIUM",
    "NP_PHONE_LANDLINE": "LOW", "IN_IFSC": "LOW", "EMAIL": "LOW", "IPV4": "LOW"
};

let ignoredTypes = JSON.parse(localStorage.getItem("dt_ignored") || "[]");

function normalizeDigits(text) {
    const devanagari = "०१२३४५६७८९";
    return text.replace(/[०-९]/g, d => "0123456789"[devanagari.indexOf(d)]);
}

function isLuhnValid(num) {
    let digits = num.replace(/\D/g, '').split('').map(Number).reverse();
    let sum = 0;
    for (let i = 0; i < digits.length; i++) {
        let d = digits[i];
        if (i % 2 === 1) {
            d *= 2;
            if (d > 9) d -= 9;
        }
        sum += d;
    }
    return sum % 10 === 0;
}

function isVerhoeffValid(num) {
    const d = [
        [0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],
        [3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],
        [6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],
        [9,8,7,6,5,4,3,2,1,0]
    ];
    const p = [
        [0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],
        [8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],
        [2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]
    ];
    let c = num.replace(/\D/g, '').split('').map(Number).reverse();
    let check = 0;
    for (let i = 0; i < c.length; i++) {
        check = d[check][p[i % 8][c[i]]];
    }
    return check === 0;
}

function maskValue(value) {
    if (value.length <= 4) return "*".repeat(value.length);
    return value.substring(0, 2) + "*".repeat(value.length - 4) + value.substring(value.length - 2);
}

function scanText(text) {
    let normalized = normalizeDigits(text);
    let findings = [];

    for (let [name, regex] of Object.entries(patterns)) {
        if (ignoredTypes.includes(name)) continue;
        
        let match;
        regex.lastIndex = 0;
        while ((match = regex.exec(normalized)) !== null) {
            let value = match[0];
            if (name === "CREDIT_CARD" && !isLuhnValid(value)) continue;
            if (name === "IN_AADHAAR" && !isVerhoeffValid(value)) continue;

            findings.push({
                type: name,
                value: value,
                severity: severity[name] || "LOW",
                start: match.index,
                end: match.index + value.length
            });
        }
    }

    findings.sort((a, b) => (b.end - b.start) - (a.end - a.start));
    let filtered = [];
    for (let f of findings) {
        let overlap = false;
        for (let existing of filtered) {
            if (Math.max(f.start, existing.start) < Math.min(f.end, existing.end)) {
                overlap = true;
                break;
            }
        }
        if (!overlap) filtered.push(f);
    }

    filtered.sort((a, b) => a.start - b.start);
    
    let risk = "NONE";
    if (filtered.some(f => f.severity === "HIGH")) risk = "HIGH";
    else if (filtered.some(f => f.severity === "MEDIUM")) risk = "MEDIUM";
    else if (filtered.length > 0) risk = "LOW";

    return { risk, findings: filtered };
}

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
    
    typingTimer = setTimeout(() => {
        const text = el.value || el.innerText;
        
        if (!text || text.length < 5) {
            if (warningBox) warningBox.style.display = "none";
            lastScannedText = "";
            return;
        }
        if (text === lastScannedText) return;
        
        lastScannedText = text;
        const data = scanText(text);

        if (data.risk === "HIGH" || data.risk === "MEDIUM") {
            createWarningBox();
            const listElement = document.getElementById("dt-list");
            listElement.innerHTML = ""; 
            
            data.findings.forEach(f => {
                const li = document.createElement("li");
                const friendlyType = f.type.replace("NP_", "").replace("IN_", "").replace(/_/g, " ");
                
                li.innerHTML = `
                    <div class="dt-item-info">
                        <span class="dt-item-type">${friendlyType}</span>
                        <span class="dt-item-value">${maskValue(f.value)}</span>
                    </div>
                    <button class="dt-ignore-btn" data-type="${f.type}">Ignore</button>
                `;
                listElement.appendChild(li);
            });

            document.querySelectorAll(".dt-ignore-btn").forEach(btn => {
                btn.addEventListener("click", (e) => {
                    const typeToIgnore = e.target.getAttribute("data-type");
                    if (!ignoredTypes.includes(typeToIgnore)) {
                        ignoredTypes.push(typeToIgnore);
                        localStorage.setItem("dt_ignored", JSON.stringify(ignoredTypes));
                    }
                    lastScannedText = "";
                    document.dispatchEvent(new Event("input"));
                });
            });

            warningBox.style.display = "block";
        } else {
            if (warningBox) warningBox.style.display = "none";
        }
    }, doneTypingInterval);
});
