/**
 * Error notification sound using Web Audio API.
 * Plays E8 Triple Emergency - 880Hz sine x 3, clinical hospital monitor style.
 */

import { playToneSequence } from '@/utils/audioUtils'

/**
 * Play a triple-beep error sound (A5 x 3).
 */
export async function playErrorSound(): Promise<void> {
  await playToneSequence([
    { frequency: 880, duration: 0.15, delay: 0, volume: 0.28 },
    { frequency: 880, duration: 0.15, delay: 0.2, volume: 0.28 },
    { frequency: 880, duration: 0.15, delay: 0.4, volume: 0.28 },
  ])
}
