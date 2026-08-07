export class SkillsRefreshSequence {
  private latest = 0;

  begin(): number {
    return ++this.latest;
  }

  invalidate(): void {
    this.latest += 1;
  }

  isCurrent(request: number): boolean {
    return request === this.latest;
  }
}
