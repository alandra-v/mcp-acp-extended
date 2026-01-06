/**
 * Notification sound using Web Audio API.
 * Plays a two-tone chime on pending approval.
 */

let audioContext: AudioContext | null = null

async function getContext(): Promise<AudioContext> {
  if (!audioContext) audioContext = new AudioContext()
  if (audioContext.state === 'suspended') {
    await audioContext.resume()
  }
  return audioContext
}

export async function playApprovalChime(): Promise<void> {
  const ctx = await getContext()
  const now = ctx.currentTime
  ;[523, 659].forEach((freq, i) => {
    const osc = ctx.createOscillator()
    const gain = ctx.createGain()
    osc.type = 'sine'
    osc.frequency.value = freq
    gain.gain.setValueAtTime(0.3, now + i * 0.12)
    gain.gain.exponentialRampToValueAtTime(0.001, now + i * 0.12 + 0.2)
    osc.connect(gain)
    gain.connect(ctx.destination)
    osc.start(now + i * 0.12)
    osc.stop(now + i * 0.12 + 0.2)
  })
}

export function useNotificationSound() {
  return { playApprovalChime }
}
