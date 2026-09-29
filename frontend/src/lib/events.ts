// App-wide UI events, so the palette, the rail and keyboard shortcuts stay decoupled.
export const openPalette = (): void => { window.dispatchEvent(new Event('securiq:palette')); };
export const toggleRail = (): void => { window.dispatchEvent(new Event('securiq:toggle-rail')); };
