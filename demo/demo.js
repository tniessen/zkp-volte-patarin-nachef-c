'use strict';

(() => {
  const tbody = document.querySelector('#stats-table tbody');
  const statusLabel = document.getElementById('status-label');

  const sodiumReady = window.sodium.ready;
  const loadWasmModule = fetch('lib.wasm').then((res) => res.arrayBuffer()).then((buf) => WebAssembly.compile(buf));

  sodiumReady.then(() => {
    document.getElementById('app-info').append(` Using libsodium ${window.sodium.SODIUM_VERSION_STRING}.`);
  });

  Promise.all([sodiumReady, loadWasmModule]).then(([_, wasmModule]) => {
    function instantiateWasm(hmacStats) {
      let instance;
      return WebAssembly.instantiate(wasmModule, {
        crypto: {
          hmacSHA256(keyPtr, dataPtr, dataSize, outPtr) {
            const mem = new Uint8Array(instance.exports.memory.buffer);
            const key = mem.slice(keyPtr, keyPtr + 32);
            const data = mem.slice(dataPtr, dataPtr + dataSize);
            const hmac = window.sodium.crypto_auth_hmacsha256_init(key);
            window.sodium.crypto_auth_hmacsha256_update(hmac, data);
            const digest = window.sodium.crypto_auth_hmacsha256_final(hmac);
            mem.set(digest, outPtr);
            hmacStats[hmacStats.currentContext]++;
          },
          randomBytes(ptr, size) {
            const bytes = window.sodium.randombytes_buf(size);
            new Uint8Array(instance.exports.memory.buffer).set(bytes, ptr);
          }
        },
        wasi_snapshot_preview1: {
          fd_seek(fd, offset, whence) {
            // TODO
          },
          fd_write(fd, iovs) {
            // TODO
          },
          fd_close(fd) {
            // TODO
          }
        }
      }).then((i) => Promise.resolve(instance = i));
    }

    function createInstance(paramsFn) {
      const hmacStats = {
        currentContext: undefined,
        prover: 0,
        verifier: 0
      };
      const transferStats = {
        prover: 0,
        verifier: 0
      };

      return instantiateWasm(hmacStats).then((wasm) => {
        function readNullTerminatedString(ptr) {
          const view = new Uint8Array(wasm.exports.memory.buffer, ptr);
          const strlen = view.indexOf(0);
          return new TextDecoder().decode(view.slice(0, strlen));
        }

        const paramsPtr = wasm.exports[paramsFn]();
        const namePtr = wasm.exports.zkp_get_params_name(paramsPtr);
        const name = readNullTerminatedString(namePtr);

        const keySpaceLog2 = wasm.exports.zkp_get_key_space_log2(paramsPtr);
        const securityExp = 1 + keySpaceLog2 / 2;
        const security = document.createElement('span');
        security.innerHTML = `2<sup>${securityExp.toFixed(1)}</sup>`;

        const privateKeyPtr = wasm.exports.zkp_generate_private_key(paramsPtr);
        const publicKeyPtr = wasm.exports.zkp_compute_public_key(privateKeyPtr);

        const proof = wasm.exports.zkp_new_proof(privateKeyPtr);

        const verification = wasm.exports.zkp_new_verification(publicKeyPtr);

        let reachedThreshold = false;
        let nRounds = 0;
        function doOneRound() {
          hmacStats.currentContext = 'prover';
          const commitments = wasm.exports.zkp_begin_round(proof);
          transferStats.prover += wasm.exports.zkp_get_commitments_size(paramsPtr);
          const q = wasm.exports.zkp_choose_question(verification);
          transferStats.verifier++;
          const answer = wasm.exports.zkp_get_answer(proof, q);
          transferStats.prover += wasm.exports.zkp_get_answer_size(paramsPtr, q);
          hmacStats.currentContext = 'verifier';
          const ok = wasm.exports.zkp_verify(verification, commitments, answer);
          if (!ok) {
            throw new Error('Verification failed');
          }
          nRounds++;
          updateRow();
          return !reachedThreshold && (reachedThreshold = (wasm.exports.zkp_get_impersonation_probability(verification) <= 2**-30));
        }

        function addCell(...content) {
          const cell = document.createElement('td');
          cell.classList.add('border', 'px-4', 'py-2', 'text-center');
          row.appendChild(cell).append(...content);
          return cell;
        }

        const row = document.createElement('tr');
        const checkbox = document.createElement('input');
        checkbox.setAttribute('type', 'checkbox');
        checkbox.checked = true;
        addCell(checkbox);
        addCell(name);
        addCell(security);
        const roundsCell = addCell();
        const impProbCell = addCell();
        const vmHeapCell = addCell();
        const transferProverCell = addCell();
        const transferVerifierCell = addCell();
        const nCommitmentsProverCell = addCell();
        const nCommitmentsVerifierCell = addCell();

        function updateRow() {
          roundsCell.textContent = nRounds;
          impProbCell.innerHTML = `2<sup>${Math.log2(wasm.exports.zkp_get_impersonation_probability(verification)).toFixed(2)}</sup>`;
          vmHeapCell.textContent = `${(wasm.exports.memory.buffer.byteLength / 1024 / 1024).toFixed(1)} MiB`;
          transferProverCell.textContent = `${(transferStats.prover / 1024).toFixed(1)} KiB`;
          transferVerifierCell.textContent = `${(transferStats.verifier / 1024).toFixed(1)} KiB`;
          nCommitmentsProverCell.textContent = `${hmacStats.prover}`;
          nCommitmentsVerifierCell.textContent = `${hmacStats.verifier}`;
        }

        updateRow();

        return {
          checkbox,
          row,
          doOneRound
        };
      });
    }

    const findParamsFns = instantiateWasm().then((wasm) => {
      return Object.keys(wasm.exports).filter((k) => k.startsWith('zkp_params_')).sort();
    });
    const createInstances = findParamsFns.then((paramsFns) => Promise.all(paramsFns.map(createInstance)));

    createInstances.then((instances) => {
      let tickInterval;

      for (const instance of instances) {
        tbody.appendChild(instance.row);
      }

      const resumeButton = document.getElementById('resume-button');
      const pauseButton = document.getElementById('pause-button');

      resumeButton.addEventListener('click', () => {
        resumeButton.disabled = true;
        pauseButton.disabled = false;
        statusLabel.textContent = 'Running';
        statusLabel.classList.remove('inactive');
        if (tickInterval === undefined) {
          tickInterval = setInterval(() => {
            tick();
          }, 50);
        }
      });

      function pause() {
        pauseButton.disabled = true;
        resumeButton.disabled = false;
        statusLabel.textContent = 'Paused';
        statusLabel.classList.add('inactive');
        if (tickInterval !== undefined) {
          clearInterval(tickInterval);
          tickInterval = undefined;
        }
      }

      pauseButton.addEventListener('click', pause);
      pause();

      let idleAvg = 100;
      function tick() {
        const startTime = Date.now();
        for (const instance of instances) {
          if (instance.checkbox.checked) {
            if (instance.doOneRound()) {
              instance.checkbox.checked = false;
              instance.row.classList.add('success');
              pause();
            }
          }
        }
        const endTime = Date.now();
        if (tickInterval !== undefined) {
          idleAvg = 0.9 * idleAvg + 0.1 * (100 - (endTime - startTime));
          statusLabel.textContent = `Running (${idleAvg.toFixed(0)} % idle)`;
        }
      }
    });
  });
})();
