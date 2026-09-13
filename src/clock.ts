// Validated clock (§7): nondecreasing accepted wall-clock ms, monotonic
// cross-check, bounded estimated error. Backwards movement or a forward jump
// beyond the configured bound makes the clock unsafe: deadline guards stop
// firing and deadline-dependent admissions return CLOCK_UNSAFE until a reviewed
// resume. Deadline-independent admissions timestamp with the last validated
// reading so event time stays nondecreasing.

export interface ClockReading {
  now: bigint;          // validated admission timestamp to record in events
  wallNow: bigint;      // actual observed wall clock
  safe: boolean;        // clock is safe for deadline evaluation
}

export class CoordinatorClock {
  private lastValidated: bigint;
  private lastWall: bigint;
  private lastMono: number;
  private unsafe = false;
  private readonly maxSkewMs: bigint;

  constructor(nowMs: bigint, maxSkewMs = 2000n) {
    this.lastValidated = nowMs;
    this.lastWall = nowMs;
    this.lastMono = performance.now();
    this.maxSkewMs = maxSkewMs;
  }

  /** Observe the wall clock now; returns the validated admission reading. */
  tick(): ClockReading {
    const wall = BigInt(Date.now());
    return this.observe(wall);
  }

  /** Observe an explicit wall-clock reading (deterministic harness path). */
  observe(wall: bigint): ClockReading {
    const mono = performance.now();
    const monoDelta = mono - this.lastMono;
    const wallDelta = Number(wall - this.lastWall);
    const skew = Math.abs(wallDelta - monoDelta);
    if (wall < this.lastValidated || wall < this.lastWall) {
      this.unsafe = true;
    } else if (monoDelta >= 0 && skew > Number(this.maxSkewMs) && wallDelta > Number(this.maxSkewMs)) {
      // forward discontinuity beyond the allowed measurement error
      this.unsafe = true;
    }
    this.lastWall = wall;
    this.lastMono = mono;
    if (this.unsafe) {
      return { now: this.lastValidated, wallNow: wall, safe: false };
    }
    if (wall > this.lastValidated) this.lastValidated = wall;
    return { now: this.lastValidated, wallNow: wall, safe: true };
  }

  isUnsafe(): boolean {
    return this.unsafe;
  }

  /** Operator-reviewed resume after clock incident evidence. */
  resume(wall: bigint): void {
    this.lastWall = wall;
    this.lastMono = performance.now();
    this.unsafe = false;
    if (wall > this.lastValidated) this.lastValidated = wall;
  }

  get lastValidatedMs(): bigint {
    return this.lastValidated;
  }
}
