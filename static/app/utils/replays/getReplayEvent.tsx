export function getPrevReplayEvent<T extends {timestamp?: string | number}>({
  items,
  targetTimestampMs,
  allowExact = false,
  allowEqual = false,
}: {
  items: T[];
  targetTimestampMs: number;
  allowEqual?: boolean;
  allowExact?: boolean;
}) {
  return items.reduce<T | undefined>((prev, item) => {
    const itemTimestampMS = +new Date(item.timestamp || '');

    if (
      itemTimestampMS > targetTimestampMs ||
      (!allowExact && itemTimestampMS === targetTimestampMs)
    ) {
      return prev;
    }
    if (
      !prev ||
      (allowEqual
        ? itemTimestampMS >= +new Date(prev.timestamp || '')
        : itemTimestampMS > +new Date(prev.timestamp || ''))
    ) {
      return item;
    }
    return prev;
  }, undefined);
}

export function getNextReplayEvent<T extends {timestamp?: string}>({
  items,
  targetTimestampMs,
  allowExact = false,
}: {
  items: T[];
  targetTimestampMs: number;
  allowExact?: boolean;
}) {
  return items.reduce<T | undefined>((found, item) => {
    const itemTimestampMS = +new Date(item.timestamp || '');

    if (
      itemTimestampMS < targetTimestampMs ||
      (!allowExact && itemTimestampMS === targetTimestampMs)
    ) {
      return found;
    }
    if (!found || itemTimestampMS < +new Date(found.timestamp || '')) {
      return item;
    }
    return found;
  }, undefined);
}
