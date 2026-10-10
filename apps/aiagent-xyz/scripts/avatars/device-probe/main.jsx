import { useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import AvatarStage from '../../../src/product/avatar/AvatarStage.jsx';
import { AVATAR_BODIES, DEFAULT_APPEARANCE } from '../../../shared/avatar-catalog.mjs';
import './probe.css';

const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function measureFrames(duration) {
  return new Promise((resolve, reject) => {
    const intervals = []; let start, previous, frame;
    const finish = () => { cancelAnimationFrame(frame); document.removeEventListener('visibilitychange', visibility); window.removeEventListener('resize', resized); };
    const visibility = () => { if (document.hidden) { finish(); reject(new Error('Keep the page visible throughout the measurement.')); } };
    const resized = () => { finish(); reject(new Error('Keep the same screen orientation during the measurement, then run again.')); };
    document.addEventListener('visibilitychange', visibility);
    window.addEventListener('resize', resized);
    const sample = (now) => {
      if (matchMedia('(prefers-reduced-motion: reduce)').matches) { finish(); reject(new Error('Reduced motion changed during the check.')); return; }
      start ??= now;
      if (previous !== undefined) intervals.push(now - previous);
      previous = now;
      if (now - start < duration) { frame = requestAnimationFrame(sample); return; }
      finish(); const sorted = [...intervals].sort((a, b) => a - b);
      resolve({ averageFps: intervals.length * 1000 / (now - start), p95FrameMs: sorted[Math.floor(sorted.length * .95)], p99FrameMs: sorted[Math.floor(sorted.length * .99)], frames: intervals.length });
    };
    frame = requestAnimationFrame(sample);
  });
}

export default function DeviceProbe() {
  const [body, setBody] = useState('robot'), [running, setRunning] = useState(false);
  const [message, setMessage] = useState('Run all three bodies on this device.'), [report, setReport] = useState(null);
  const [device, setDevice] = useState('');
  const ready = useRef(null), stats = useRef(null);
  const definition = AVATAR_BODIES.find((item) => item.id === body);
  const appearance = { ...DEFAULT_APPEARANCE, body, asset_revision: definition.revision, finish: definition.finishes[0].id };
  const run = async () => {
    if (matchMedia('(prefers-reduced-motion: reduce)').matches) { setMessage('Animation respects reduced motion. Turn that preference off for this timing check.'); return; }
    setRunning(true); setReport(null);
    const result = { device: device.trim(), measuredAt: new Date().toISOString(), userAgent: navigator.userAgent, viewport: [innerWidth, innerHeight], devicePixelRatio, cases: [] };
    try {
      for (const item of AVATAR_BODIES) {
        const alreadyLoaded = ready.current === item.id && document.querySelector('.avatar-stage')?.dataset.status === 'ready';
        setBody(item.id); const started = performance.now();
        setMessage(`Loading ${item.label}…`);
        while (ready.current !== item.id || document.querySelector('.avatar-stage')?.dataset.status !== 'ready') {
          if (performance.now() - started > 30000) throw new Error(`${item.label} did not load within 30 seconds.`);
          await pause(50);
        }
        const readyMs = performance.now() - started;
        await pause(1500); setMessage(`Measuring ${item.label} for 10 seconds. Keep this page visible.`);
        const measured = await measureFrames(10000);
        const canvas = document.querySelector('.avatar-stage-canvas canvas'), gl = canvas.getContext('webgl2');
        const debug = gl.getExtension('WEBGL_debug_renderer_info');
        result.cases.push({ body: item.id, quality: innerWidth < 768 ? 'mobile' : 'desktop', readyWaitMs: readyMs, alreadyLoaded, canvas: [canvas.width, canvas.height],
          gpu: gl.getParameter(debug ? debug.UNMASKED_RENDERER_WEBGL : gl.RENDERER), ...measured, drawCalls: stats.current?.calls, renderedTriangles: stats.current?.triangles });
        setReport({ ...result, cases: [...result.cases] });
      }
      setMessage('Check complete. Save the result with the device model.');
    } catch (error) { setMessage(error.message); }
    finally { setRunning(false); }
  };
  const download = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }));
    const link = document.createElement('a'); link.href = url; link.download = 'avatar-device-result.json'; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  return <main><header><p>Avatar qualification</p><h1>Device check</h1><p>{message}</p>
    <label>Device model<input value={device} onChange={(event) => setDevice(event.target.value)} disabled={running} placeholder="For example, Pixel 7a" /></label></header>
    <AvatarStage key={body} appearance={appearance} onReady={({ body }) => { ready.current = body; }} onProgress={(value) => { stats.current = value; }} />
    <nav aria-label="Device check controls"><button disabled={running || !device.trim()} onClick={run}>{running ? 'Measuring…' : 'Run device check'}</button>
      {report && <button onClick={download}>Save results</button>}</nav>
    {report && <table><thead><tr><th>Body</th><th>FPS</th><th>95% frame</th></tr></thead><tbody>{report.cases.map((item) => <tr key={item.body}><th>{item.body}</th><td>{item.averageFps.toFixed(1)}</td><td>{item.p95FrameMs.toFixed(1)} ms</td></tr>)}</tbody></table>}
  </main>;
}
createRoot(document.getElementById('root')).render(<DeviceProbe />);
