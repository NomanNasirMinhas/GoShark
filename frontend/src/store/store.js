// store.js
import { writable } from 'svelte/store';

export const userStore = writable({
    capture_iface: '',
    capture_promisc: false,
  filter: '',
  requests: [],
});