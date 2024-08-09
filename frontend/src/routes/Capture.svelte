<script>
  // @ts-nocheck

  import logo from "./../assets/images/logo.jpeg";
  import { userStore } from "./../store/store";
  import {
    Table,
    TableBody,
    TableBodyCell,
    TableBodyRow,
    TableHead,
    TableHeadCell,
    Drawer,
    CloseButton,
    Input,
    Navbar,
    NavBrand,
    NavHamburger,
    Button,
    Checkbox,
    AccordionItem,
    Accordion, Toast, Modal
  } from "flowbite-svelte";
  import {
    InfoCircleSolid,
    ArrowRightOutline,
    SearchSolid,
    PlaySolid,
    StopSolid,
    CheckCircleSolid,
    ExclamationCircleSolid,
  } from "flowbite-svelte-icons";
  import {
    Greet,
    StartCapture,
    StopCapture,
  } from "../../wailsjs/go/main/App.js";
  import { onMount, onDestroy } from "svelte";
  import { writable } from "svelte/store";
  import { sineIn } from "svelte/easing";
  import { l2_protocols, appProtocols } from "./../consts/protocols";

  const WS_URL = "ws://localhost:4444/ws";
  const ac_transitionParamsBottom = { y: 320, duration: 200, easing: sineIn };

  const requests = writable([]);
  const alerts = writable([]);
  let scroll_to_bottom = true;
  let show_with_alerts = false;
  let ac_hidden8 = true;
  let ac_current_packet = null;
  let capture_started = false;
  let export_file = $userStore.capture_export;
  let searchTerm = "";
  let active_row_color = "#063970";
  let active_row_idx;

  let ws;
  let is_loading = false
  let toast_message = ""
  let toast_color = ""

  // Reactive statements
  $: filteredItems = $requests.filter((item) =>
    JSON.stringify(item.packet_string).toLowerCase().includes(searchTerm.toLowerCase())
  );
  $: capture_iface = $userStore.capture_iface;
  $: capture_promisc = $userStore.capture_promisc;

  // Lifecycle hooks
  onMount(() => connect());
  onDestroy(() => ws?.close());

  function base64ToMacAddress(base64) {
    try{
  // Decode the base64 string to a binary string
  const binaryString = atob(base64);

  // Convert binary string to a hexadecimal string
  const hexArray = [];
  for (let i = 0; i < binaryString.length; i++) {
    const hex = binaryString.charCodeAt(i).toString(16).padStart(2, '0');
    hexArray.push(hex);
  }

  // Ensure that we have exactly 6 bytes (12 hex characters)
  if (hexArray.length !== 6) {
    //console.log("Invalid Base64 string for MAC address conversion");
  }

  // Format the hex string as a MAC address
  const macAddress = hexArray.join(':').toUpperCase();

  return macAddress;
} catch(e){
  console.log("Mac Parse Exception", e)
}
}

  function decodeBase64(base64, format) {
    //console.log("Base64", base64);
    let result;
    // Decode the base64 string to a binary string
    const binaryString = atob(base64);

    // Convert binary string to a Uint8Array
    const byteArray = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      byteArray[i] = binaryString.charCodeAt(i);
    }
    switch (format) {
      case "hex":
        result = Array.from(byteArray)
          .map((byte) => byte.toString(16).padStart(2, "0"))
          .join(" ")
          .toUpperCase();
        break;

      case "ascii":
        result = byteArray.reduce(
          (acc, byte) => acc + String.fromCharCode(byte),
          ""
        );
        break;

      case "utf-8":
        const utf8Decoder = new TextDecoder("utf-8");
        result = utf8Decoder.decode(byteArray);
        break;

      default:
        return;
    }
    return result;
    // Convert binary string to a UTF-8 string
  }

  function connect() {
    ws = new WebSocket(WS_URL);

    ws.addEventListener("message", (event) => {
      const pcapData = JSON.parse(event.data);
      if(pcapData.layers){
        console.log("Got Packet Details for Packet Id: ", pcapData.packet_id)
        ac_current_packet = pcapData
        ac_hidden8 = false
      } else{
        //console.log("Received message from server:", pcapData);
        requests.update((old) => [...old, pcapData]);
      }
      if (scroll_to_bottom) scrollToEnd();
    });

    ws.addEventListener("error", (err) => console.log("WebSocket error:", err));
    ws.addEventListener("close", () =>
      console.log("WebSocket connection closed")
    );

    StartCapture(capture_iface, capture_promisc, "", export_file, true);
    capture_started = true;
  }

  async function toggleCapture() {
    if (capture_started) {
      //console.log("Stopping capture");
      is_loading = true
      let res = await StopCapture();
      if(res){
        is_loading=false
      }

      ws.close();
      capture_started = false;
      //console.log("Capture stopped");
    } else {
      //console.log("Starting capture");
      requests.set([]);
      connect();
      capture_started = true;
      StartCapture(capture_iface, capture_promisc, "", export_file, true);
      //console.log("Capture started");
    }
  }

  function scrollToEnd() {
    const container = document.getElementById("packets_div");
    if (container) {
      container.scrollTop = container.scrollHeight;
    }
  }
  function stripLeadingDashes(str) {
    return str.replace(/^--/, "");
  }
</script>

<main>
  <Modal title="Loading..." bind:open={is_loading} class="bg-blue-950 text-base leading-relaxed font-mono text-orange-500">
    <p class="">Please Wait while the operation completes.</p>    
  </Modal>
  <!-- Drawer -->
  {#if ac_current_packet}
    <Drawer
      placement="bottom"
      width="w-full max-h-96 bg-slate-950"
      transitionType="fly"
      transitionParams={ac_transitionParamsBottom}
      bind:hidden={ac_hidden8}
      id="sidebar8"
    >
      <div class="flex items-center">
        <h5
          id="drawer-label"
          class="inline-flex items-center mb-4 text-base font-semibold font-mono text-white"
        >
          <InfoCircleSolid class="w-5 h-5 me-2.5 font-mono text-white" /> Info
        </h5>
        <CloseButton
          on:click={() => (ac_hidden8 = true)}
          class="mb-4 dark:text-white"
        />
      </div>
      <div class="flex flex-row justify-between">
        <div class="w-2/3 border-2 border-blue-900 p-8 bg-blue-950">
          <Accordion
            activeClass="bg-blue-900 dark:bg-gray-800 text-blue-600 dark:text-white focus:ring-4 focus:ring-blue-200 dark:focus:ring-blue-800"
            inactiveClass="text-gray-500 dark:text-gray-400 hover:bg-blue-900 dark:hover:bg-gray-800"
          >
            {#each ac_current_packet.layers as l}
              {#if l.name}
                <AccordionItem>
                  <span
                    slot="header"
                    class="text-xs font-bold font-sans text-white hover:bg-blue-950"
                    >{l.name}
                  </span>
                  {#if l.name !== "Payload"}
                    <div class="grid grid-cols-4 gap-4">
                      {#each Object.keys(l.layer) as key}
                        {#if key != "Contents" && key != "Options" && key != "Payload" && l.layer[key] != null}
                          <p class="text-xs text-white mr-8">
                            <span class="font-bold font-serif">{key}: </span>
                            <span class="font-thin font-serif"
                              >{base64ToMacAddress(l.layer[key]) ? base64ToMacAddress(l.layer[key]) : l.layer[key]}</span
                            >
                          </p>
                        {/if}
                      {/each}
                    </div>
                  {/if}

                  {#if l.name === "Payload"}
                    <div class="mt-4">
                      {#if l.layer}
                        <!-- <h3 class="text-sm font-bold font-serif text-white">
                          Data
                        </h3> -->
                        <div class="flex flex-row break-words">
                          <code
                            class="text-xs font-thin font-serif text-white break-words w-1/2 text-justify"
                          >
                            {decodeBase64(l.layer, "hex")}
                          </code>

                          <p class="w-16"></p>

                          <code
                            class="text-xs font-thin font-serif text-white break-words w-1/2 text-justify"
                          >
                            {decodeBase64(l.layer, "ascii")}
                          </code>
                        </div>
                      {/if}
                    </div>
                  {:else}
                    <div class="mt-8">
                      {#if l.layer.Contents}
                        <!-- <h3 class="text-sm font-bold font-serif text-white">
                          Data
                        </h3> -->
                        <div class="flex flex-row break-words">
                          <code
                            class="text-xs font-thin font-serif text-white break-words w-1/2 text-justify"
                          >
                            {decodeBase64(l.layer.Contents, "hex")}
                          </code>

                          <p class="w-16"></p>

                          <code
                            class="text-xs font-thin font-serif text-white break-words w-1/2 text-justify"
                          >
                            {decodeBase64(l.layer.Contents, "ascii")}
                          </code>
                        </div>
                      {/if}
                    </div>
                  {/if}
                </AccordionItem>
              {/if}
            {/each}
          </Accordion>
        </div>

        <div class="w-1/3 ml-8 border-2 border-blue-900 p-8 bg-teal-800">
          {#if ac_current_packet.has_alert}
            {#if ac_current_packet.suricata_alert && ac_current_packet.suricata_alert.length > 0}
              <p class="text-sm font-bold font-mono text-white mb-4">
                Yara Rules
              </p>
              {#each ac_current_packet.suricata_alert as sa}
                <p class="text-sm text-left font-mono text-white mb-1">
                  {sa.alert_msg}
                </p>
              {/each}
            {/if}

            {#if ac_current_packet.yara_alert && ac_current_packet.yara_alert.length > 0}
              <p class="text-sm font-bold font-mono text-white mb-4 mt-8">
                Suricata Rules
              </p>
              {#each ac_current_packet.yara_alert as ya}
                <p class="text-sm text-left font-mono text-white mb-1">
                  {ya.alert_msg}
                </p>
              {/each}
            {/if}
          {:else}
            <p class="text-sm font-bold font-mono text-white mb-4">
              No Alert Found
            </p>
          {/if}
          <p class="mt-8 text-xs font-thin font-serif text-white break-words text-justify">{ac_current_packet.packet_string}</p>
        </div>
      </div>
      <!-- <Button color="light" href="/">Learn more</Button>
            <Button href="/" class="px-4">Get access <ArrowRightOutline class="w-5 h-5 ms-2" /></Button> -->
    </Drawer>
  {/if}

  <!-- Navbar -->
  <Navbar class="flex flex-row justify-start fixed top-0 left-0 right-0 z-10">
    <NavBrand href="/">
      <img src={logo} class="me-3 h-6 sm:h-9" alt="Flowbite Logo" />
      <span
        class="self-center whitespace-nowrap text-xl font-semibold dark:text-white"
        >Home</span
      >
    </NavBrand>
    <div class="w-64">
      <Input type="text" placeholder="Enter a filter" bind:value={searchTerm}>
        <SearchSolid
          slot="right"
          class="w-5 h-5 text-blue-500 dark:text-gray-400"
        />
      </Input>
    </div>
    <div class="flex md:order-2">
      <div class="flex flex-col">
        <Checkbox
          class="mr-16"
          checked={show_with_alerts}
          on:click={() => {
            show_with_alerts = !show_with_alerts;
            show_with_alerts ? (searchTerm = "has_alert") : (searchTerm = "");
          }}>Alerts</Checkbox
        >
        <Checkbox
          class="mr-16"
          checked={scroll_to_bottom}
          on:click={() => (scroll_to_bottom = !scroll_to_bottom)}
          >Scroll To End</Checkbox
        >
      </div>
      <div class="flex flex-col">
        <Button
          size="sm"
          color={capture_started ? "red" : "green"}
          on:click={toggleCapture}
        >
          {#if capture_started}
            <StopSolid class="w-5 h-5 me-2" /> Stop Capturing
          {:else}
            <PlaySolid class="w-5 h-5 me-2" /> Start Capturing
          {/if}
        </Button>
        <p class="text-sm font-mono font-thin">Packets: {$requests.length}</p>
      </div>
      <NavHamburger />
    </div>
  </Navbar>

  <!-- Packets Table -->
  <div class="packets_div fixed top-36 left-0 right-0 z-10" id="packets_div">
    <table>
      <thead>
        <tr>
          <th>No.</th>
          <!-- <th>*</th> -->
          <th>Timestamp</th>
          <th>Length</th>
          <th>Source</th>
          <!-- <th>Source Addr</th> -->
          <th>Destination</th>
          <!-- <th>Destination Addr</th> -->
          <th>Transport</th>
          <th>Protocol</th>
          <th>Port Flow</th>
          <!-- <th>Details</th> -->
        </tr>
      </thead>
      <tbody>
        {#each filteredItems as item, idx}
          <tr
            style="background-color: {active_row_idx === idx
              ? active_row_color
              : item.color
                ? item.color
                : item.l2_protocol === 'TCP'
                  ? '#2596be'
                  : '#e28743'};
                    color: {active_row_idx === idx ? '#ffffff' : '#000000'};
                    "
            on:mouseenter={() => {
              active_row_idx = idx;
            }}
            on:mouseleave={() => {
              active_row_idx = null;
            }}
            on:click={() => {              
              ac_current_packet = item;            
              ws.send(`pack-info_${item.packet_id}`)
              // ac_hidden8 = false;
            }}
          >
            <td>{item.packet_id}</td>            
              <td>{item.timestamp}</td>
              <td>{item.length || "N/A"}</td>
            <td>{item.source}</td>            
            <td
              >{item.destination}</td
            >            
            <td>
              {item.protocol}
            </td>
            <td>
              {item.app_protocol}
            </td>

            <td>
              {item.src_port ? item.src_port + " -> " + item.dst_port : "N/A"}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
</main>

<style>
  .packets_div {
    margin: 1.5rem auto;
    width: 95%;
    max-height: 80vh;
    overflow-y: scroll;
    overflow-wrap: break-word;
    border: 1px solid #03104e;
    border-radius: 5px;
    padding: 10px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-family: Arial, sans-serif;
  }

  thead {
    background-color: #2c2c2c;
    color: #ffffff;
    position: sticky;
    top: -20px;
    z-index: 1;
  }

  th {
    border: 1px solid #444;
    padding: 10px;
    text-align: left;
    font-size: 14px;
    font-weight: bold;
  }

  tbody tr:nth-child(even) {
    background-color: #f5f5f5;
  }

  tbody tr:nth-child(odd) {
    background-color: #ffffff;
  }

  td {
    border: 1px solid #ddd;
    padding: 8px;
    text-align: left;
    font-size: 12px;
    width: min-content;
    padding: 0px;
    padding-left: 5px;
    cursor: pointer;
  }

  /* td:hover {
    background-color: #90bc78;
} */

  tbody tr:hover {
    background-color: #e0e0e0;
  }
</style>
