// Robotic sound engine — synthesized with the Web Audio API, no audio files.
// Every sound is triggered by a user action, so autoplay policies are satisfied.

let ctx = null
let master = null

const getCtx = () => {
  if (!ctx) {
    ctx = new (window.AudioContext || window.webkitAudioContext)()
    master = ctx.createGain()
    master.gain.value = 0.15
    master.connect(ctx.destination)
  }
  if (ctx.state === 'suspended') ctx.resume()
  return ctx
}

// One robotic voice: a square wave with a slight detuned twin for a machine feel
const voice = (freq, startAt, duration, { type = 'square', vol = 1, slideTo = null } = {}) => {
  const c = getCtx()
  const t = c.currentTime + startAt

  const gain = c.createGain()
  gain.gain.setValueAtTime(0, t)
  gain.gain.linearRampToValueAtTime(vol, t + 0.01)
  gain.gain.setValueAtTime(vol, t + duration - 0.02)
  gain.gain.linearRampToValueAtTime(0, t + duration)
  gain.connect(master)

  for (const detune of [0, 8]) {
    const osc = c.createOscillator()
    osc.type = type
    osc.frequency.setValueAtTime(freq, t)
    osc.detune.value = detune
    if (slideTo) osc.frequency.exponentialRampToValueAtTime(slideTo, t + duration)
    osc.connect(gain)
    osc.start(t)
    osc.stop(t + duration + 0.02)
  }
}

export const sfx = {
  // Short blip for navigation / button presses
  click() {
    voice(880, 0, 0.06, { vol: 0.5 })
  },

  // "Beep-boop" — an action is being processed
  process() {
    voice(392, 0, 0.09)
    voice(523, 0.11, 0.09)
  },

  // Rising confirmation — action succeeded
  success() {
    voice(523, 0, 0.08)
    voice(659, 0.09, 0.08)
    voice(784, 0.18, 0.14)
  },

  // Harsh descending buzz — something failed
  error() {
    voice(233, 0, 0.18, { type: 'sawtooth', slideTo: 110 })
    voice(196, 0.2, 0.25, { type: 'sawtooth', slideTo: 98 })
  },

  // "Access granted" — login sequence
  login() {
    voice(330, 0, 0.1)
    voice(494, 0.12, 0.1)
    voice(659, 0.24, 0.1)
    voice(988, 0.36, 0.22)
  },

  // "System shutdown" — logout
  logout() {
    voice(659, 0, 0.1)
    voice(494, 0.12, 0.1)
    voice(330, 0.24, 0.22, { slideTo: 220 })
  },
}
