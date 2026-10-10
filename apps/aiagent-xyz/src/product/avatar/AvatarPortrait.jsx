import { useState } from 'react';
import { DEFAULT_APPEARANCE, avatarPortrait } from '../../../shared/avatar-catalog.mjs';

export default function AvatarPortrait({ avatar, name = 'Worker', className = '', ...props }) {
  const source = avatar?.portrait_ref || avatarPortrait(DEFAULT_APPEARANCE);
  const [failedSource, setFailedSource] = useState(null);
  return failedSource === source
    ? <span className={className} role="img" aria-label={`${name} portrait unavailable`}>{name.slice(0, 1).toUpperCase()}</span>
    : <img className={className} src={source} alt={`${name} avatar`} width="128" height="128" loading="lazy" decoding="async" onError={() => setFailedSource(source)} {...props} />;
}
