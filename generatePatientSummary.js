// generatePatientSummary.js
// Rule-based clinical pattern detector — no AI, pure JavaScript logic.

function generatePatientSummary(visits) {
  if (!visits || visits.length < 2) {
    return null;
  }

  const findings = [];

  // sort oldest → newest so trends make sense
  const sorted = [...visits].sort(
    (a, b) => new Date(a.createdAt) - new Date(b.createdAt)
  );

  // ── 1. REPEATED COMPLAINTS ──
  const complaintCounts = {};
  sorted.forEach(v => {
    if (v.complaint) {
      const key = v.complaint.trim().toLowerCase();
      complaintCounts[key] = (complaintCounts[key] || 0) + 1;
    }
  });
  Object.entries(complaintCounts).forEach(([complaint, count]) => {
    if (count >= 2) {
      findings.push(`Recurring complaint: "${complaint}" reported ${count} times.`);
    }
  });

  // ── 2. RECURRING DIAGNOSES ──
  const diagnosisCounts = {};
  sorted.forEach(v => {
    if (v.diagnosis) {
      const key = v.diagnosis.trim().toLowerCase();
      diagnosisCounts[key] = (diagnosisCounts[key] || 0) + 1;
    }
  });
  Object.entries(diagnosisCounts).forEach(([diagnosis, count]) => {
    if (count >= 2) {
      findings.push(`Recurring diagnosis: "${diagnosis}" across ${count} visits.`);
    }
  });

  // ── 3. RECURRING MEDICATIONS ──
  const medCounts = {};
  sorted.forEach(v => {
    if (v.prescription) {
      const key = v.prescription.trim().toLowerCase();
      medCounts[key] = (medCounts[key] || 0) + 1;
    }
  });
  Object.entries(medCounts).forEach(([med, count]) => {
    if (count >= 2) {
      findings.push(`Repeated prescription: "${med}" given ${count} times — may need treatment review.`);
    }
  });

  // ── 4. BLOOD PRESSURE TREND ──
  const bpReadings = sorted
    .filter(v => v.vitals && v.vitals.bloodPressure)
    .map(v => {
      const match = String(v.vitals.bloodPressure).match(/(\d+)\s*\/\s*(\d+)/);
      if (!match) return null;
      return { systolic: parseInt(match[1]), diastolic: parseInt(match[2]), date: v.createdAt };
    })
    .filter(Boolean);

  if (bpReadings.length >= 2) {
    const first = bpReadings[0];
    const last  = bpReadings[bpReadings.length - 1];

    const highCount = bpReadings.filter(r => r.systolic >= 140 || r.diastolic >= 90).length;

    if (highCount >= 2) {
      findings.push(`Elevated blood pressure recorded in ${highCount} of ${bpReadings.length} visits — possible chronic hypertension.`);
    }

    if (last.systolic - first.systolic >= 15) {
      findings.push(`Blood pressure trending upward (${first.systolic}/${first.diastolic} → ${last.systolic}/${last.diastolic}).`);
    } else if (first.systolic - last.systolic >= 15) {
      findings.push(`Blood pressure trending downward (${first.systolic}/${first.diastolic} → ${last.systolic}/${last.diastolic}).`);
    }
  }

  // ── 5. WEIGHT CHANGE ──
  const weights = sorted
    .filter(v => v.vitals && v.vitals.weight)
    .map(v => ({ weight: parseFloat(v.vitals.weight), date: v.createdAt }))
    .filter(w => !isNaN(w.weight));

  if (weights.length >= 2) {
    const first = weights[0].weight;
    const last  = weights[weights.length - 1].weight;
    const diff  = last - first;
    const pctChange = (Math.abs(diff) / first) * 100;

    if (pctChange >= 7) {
      const direction = diff > 0 ? "gain" : "loss";
      findings.push(`Notable weight ${direction}: ${first}kg → ${last}kg (${pctChange.toFixed(1)}% change).`);
    }
  }

  // ── 6. TEMPERATURE / FEVER PATTERN ──
  const temps = sorted
    .filter(v => v.vitals && v.vitals.temperature)
    .map(v => parseFloat(v.vitals.temperature))
    .filter(t => !isNaN(t));

  const feverCount = temps.filter(t => t >= 38).length;
  if (feverCount >= 2) {
    findings.push(`Recurring fever recorded in ${feverCount} visits (≥38°C).`);
  }

  // ── 7. REPEATED LAB REQUESTS ──
  const testCounts = {};
  sorted.forEach(v => {
    if (v.tests) {
      const key = v.tests.trim().toLowerCase();
      testCounts[key] = (testCounts[key] || 0) + 1;
    }
  });
  Object.entries(testCounts).forEach(([test, count]) => {
    if (count >= 2) {
      findings.push(`Lab test "${test}" requested ${count} times — consider reviewing prior results.`);
    }
  });

  // ── 8. VISIT FREQUENCY (deterioration signal) ──
  if (sorted.length >= 3) {
    const gaps = [];
    for (let i = 1; i < sorted.length; i++) {
      const days = (new Date(sorted[i].createdAt) - new Date(sorted[i - 1].createdAt)) / (1000 * 60 * 60 * 24);
      gaps.push(days);
    }
    const recentGap = gaps[gaps.length - 1];
    const earlierAvg = gaps.slice(0, -1).reduce((a, b) => a + b, 0) / (gaps.length - 1);

    if (recentGap < earlierAvg / 2 && recentGap < 14) {
      findings.push(`Visit frequency increasing — patient returning sooner than usual, may indicate worsening condition.`);
    }
  }

  if (findings.length === 0) {
    return null;
  }

  return findings.join(" ");
}

module.exports = generatePatientSummary;