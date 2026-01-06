/**
 * Error notification sound using Web Audio API.
 * Plays E8 Triple Emergency - 880Hz sine × 3, clinical hospital monitor style.
 */

let audioContext: AudioContext | null = null

async function getContext(): Promise<AudioContext> {
  if (!audioContext) audioContext = new AudioContext()
  if (audioContext.state === 'suspended') {
    await audioContext.resume()
  }
  return audioContext
}

export async function playErrorSound(): Promise<void> {
  const ctx = await getContext()
  const now = ctx.currentTime

  // Triple Emergency: 880Hz sine × 3
  ;[0, 1, 2].forEach((i) => {
    const osc = ctx.createOscillator()
    const gain = ctx.createGain()
    osc.type = 'sine'
    osc.frequency.value = 880
    const start = now + i * 0.2
    gain.gain.setValueAtTime(0.28, start)
    gain.gain.exponentialRampToValueAtTime(0.001, start + 0.15)
    osc.connect(gain)
    gain.connect(ctx.destination)
    osc.start(start)
    osc.stop(start + 0.15)
  })
}

export interface UseErrorSoundResult {
  playErrorSound: () => Promise<void>
}

export function useErrorSound(): UseErrorSoundResult {
  return { playErrorSound }
}
