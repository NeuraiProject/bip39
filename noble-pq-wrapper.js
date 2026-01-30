// Wrapper to expose @noble/post-quantum ml_dsa44 for browser use
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';

// Export for module systems
export { ml_dsa44 };

// The bundle will be created with --global-name=NoblePQ
// So we need to expose ml_dsa44 globally after the script loads
// This is done via a self-executing pattern at the end of the bundle
