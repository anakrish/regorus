(declare-fun |defined_input.containers[1]| () Bool)
(declare-fun |input.volumes[2].encrypted| () Bool)
(declare-fun |defined_input.volumes[2].encrypted| () Bool)
(declare-fun |input.volumes[2].id| () String)
(declare-fun |input.containers[1].volume_ids[1]| () String)
(declare-fun |defined_input.containers[1].volume_ids[1]| () Bool)
(declare-fun |input.containers[1].volume_ids[0]| () String)
(declare-fun |defined_input.containers[1].volume_ids[0]| () Bool)
(declare-fun |defined_input.volumes[2].id| () Bool)
(declare-fun |defined_input.containers[1].volume_ids| () Bool)
(declare-fun |defined_input.volumes[2]| () Bool)
(declare-fun |input.volumes[1].encrypted| () Bool)
(declare-fun |defined_input.volumes[1].encrypted| () Bool)
(declare-fun |input.volumes[1].id| () String)
(declare-fun |defined_input.volumes[1].id| () Bool)
(declare-fun |defined_input.volumes[1]| () Bool)
(declare-fun |input.volumes[0].encrypted| () Bool)
(declare-fun |defined_input.volumes[0].encrypted| () Bool)
(declare-fun |input.volumes[0].id| () String)
(declare-fun |defined_input.volumes[0].id| () Bool)
(declare-fun |defined_input.volumes[0]| () Bool)
(declare-fun |defined_input.containers[0]| () Bool)
(declare-fun |input.containers[0].volume_ids[0]| () String)
(declare-fun |defined_input.containers[0].volume_ids[0]| () Bool)
(declare-fun |input.containers[0].volume_ids[1]| () String)
(declare-fun |defined_input.containers[0].volume_ids[1]| () Bool)
(declare-fun |defined_input.containers[0].volume_ids| () Bool)
(declare-fun |defined_input.containers[2]| () Bool)
(declare-fun |input.containers[2].volume_ids[0]| () String)
(declare-fun |defined_input.containers[2].volume_ids[0]| () Bool)
(declare-fun |input.containers[2].volume_ids[1]| () String)
(declare-fun |defined_input.containers[2].volume_ids[1]| () Bool)
(declare-fun |defined_input.containers[2].volume_ids| () Bool)
(declare-fun |input.containers[1].name| () String)
(declare-fun |input.containers[0].name| () String)
(declare-fun |defined_input.containers[1].name| () Bool)
(declare-fun |input.hosts[2].public| () Bool)
(declare-fun |defined_input.hosts[2].public| () Bool)
(declare-fun |input.containers[1].host_id| () String)
(declare-fun |input.hosts[2].id| () String)
(declare-fun |defined_input.containers[1].host_id| () Bool)
(declare-fun |defined_input.hosts[2].id| () Bool)
(declare-fun |defined_input.hosts[2]| () Bool)
(declare-fun |input.hosts[1].public| () Bool)
(declare-fun |defined_input.hosts[1].public| () Bool)
(declare-fun |input.hosts[1].id| () String)
(declare-fun |defined_input.hosts[1].id| () Bool)
(declare-fun |defined_input.hosts[1]| () Bool)
(declare-fun |input.hosts[0].public| () Bool)
(declare-fun |defined_input.hosts[0].public| () Bool)
(declare-fun |input.hosts[0].id| () String)
(declare-fun |defined_input.hosts[0].id| () Bool)
(declare-fun |defined_input.hosts[0]| () Bool)
(declare-fun |input.containers[1].privileged| () Bool)
(declare-fun |defined_input.containers[1].privileged| () Bool)
(declare-fun |defined_input.containers[0].name| () Bool)
(declare-fun |input.containers[0].host_id| () String)
(declare-fun |defined_input.containers[0].host_id| () Bool)
(declare-fun |input.containers[0].privileged| () Bool)
(declare-fun |defined_input.containers[0].privileged| () Bool)
(declare-fun |input.containers[2].name| () String)
(declare-fun |defined_input.containers[2].name| () Bool)
(declare-fun |input.containers[2].host_id| () String)
(declare-fun |defined_input.containers[2].host_id| () Bool)
(declare-fun |input.containers[2].privileged| () Bool)
(declare-fun |defined_input.containers[2].privileged| () Bool)
(declare-fun defined_input.containers () Bool)
(declare-fun defined_input.hosts () Bool)
(declare-fun defined_input.volumes () Bool)
(assert (let ((a!1 (and (and true |defined_input.containers[2]|)
                |defined_input.volumes[0]|
                |defined_input.containers[2].volume_ids|
                |defined_input.volumes[0].id|
                (or (and |defined_input.containers[2].volume_ids[1]|
                         (= |input.containers[2].volume_ids[1]|
                            |input.volumes[0].id|))
                    (and |defined_input.containers[2].volume_ids[0]|
                         (= |input.containers[2].volume_ids[0]|
                            |input.volumes[0].id|)))
                (and |defined_input.volumes[0].encrypted|
                     (= |input.volumes[0].encrypted| false))
                |defined_input.containers[2]|))
      (a!2 (and (and true |defined_input.containers[2]|)
                |defined_input.volumes[1]|
                |defined_input.containers[2].volume_ids|
                |defined_input.volumes[1].id|
                (or (and |defined_input.containers[2].volume_ids[1]|
                         (= |input.containers[2].volume_ids[1]|
                            |input.volumes[1].id|))
                    (and |defined_input.containers[2].volume_ids[0]|
                         (= |input.containers[2].volume_ids[0]|
                            |input.volumes[1].id|)))
                (and |defined_input.volumes[1].encrypted|
                     (= |input.volumes[1].encrypted| false))
                |defined_input.containers[2]|))
      (a!3 (and (and true |defined_input.containers[2]|)
                |defined_input.volumes[2]|
                |defined_input.containers[2].volume_ids|
                |defined_input.volumes[2].id|
                (or (and |defined_input.containers[2].volume_ids[1]|
                         (= |input.containers[2].volume_ids[1]|
                            |input.volumes[2].id|))
                    (and |defined_input.containers[2].volume_ids[0]|
                         (= |input.containers[2].volume_ids[0]|
                            |input.volumes[2].id|)))
                (and |defined_input.volumes[2].encrypted|
                     (= |input.volumes[2].encrypted| false))
                |defined_input.containers[2]|))
      (a!4 (and (and true |defined_input.containers[0]|)
                |defined_input.volumes[0]|
                |defined_input.containers[0].volume_ids|
                |defined_input.volumes[0].id|
                (or (and |defined_input.containers[0].volume_ids[1]|
                         (= |input.containers[0].volume_ids[1]|
                            |input.volumes[0].id|))
                    (and |defined_input.containers[0].volume_ids[0]|
                         (= |input.containers[0].volume_ids[0]|
                            |input.volumes[0].id|)))
                (and |defined_input.volumes[0].encrypted|
                     (= |input.volumes[0].encrypted| false))
                |defined_input.containers[0]|))
      (a!5 (and (and true |defined_input.containers[0]|)
                |defined_input.volumes[1]|
                |defined_input.containers[0].volume_ids|
                |defined_input.volumes[1].id|
                (or (and |defined_input.containers[0].volume_ids[1]|
                         (= |input.containers[0].volume_ids[1]|
                            |input.volumes[1].id|))
                    (and |defined_input.containers[0].volume_ids[0]|
                         (= |input.containers[0].volume_ids[0]|
                            |input.volumes[1].id|)))
                (and |defined_input.volumes[1].encrypted|
                     (= |input.volumes[1].encrypted| false))
                |defined_input.containers[0]|))
      (a!6 (and (and true |defined_input.containers[0]|)
                |defined_input.volumes[2]|
                |defined_input.containers[0].volume_ids|
                |defined_input.volumes[2].id|
                (or (and |defined_input.containers[0].volume_ids[1]|
                         (= |input.containers[0].volume_ids[1]|
                            |input.volumes[2].id|))
                    (and |defined_input.containers[0].volume_ids[0]|
                         (= |input.containers[0].volume_ids[0]|
                            |input.volumes[2].id|)))
                (and |defined_input.volumes[2].encrypted|
                     (= |input.volumes[2].encrypted| false))
                |defined_input.containers[0]|))
      (a!7 (and (and true |defined_input.containers[1]|)
                |defined_input.volumes[0]|
                |defined_input.containers[1].volume_ids|
                |defined_input.volumes[0].id|
                (or (and |defined_input.containers[1].volume_ids[0]|
                         (= |input.containers[1].volume_ids[0]|
                            |input.volumes[0].id|))
                    (and |defined_input.containers[1].volume_ids[1]|
                         (= |input.containers[1].volume_ids[1]|
                            |input.volumes[0].id|)))
                (and |defined_input.volumes[0].encrypted|
                     (= |input.volumes[0].encrypted| false))
                |defined_input.containers[1]|))
      (a!8 (and (and true |defined_input.containers[1]|)
                |defined_input.volumes[1]|
                |defined_input.containers[1].volume_ids|
                |defined_input.volumes[1].id|
                (or (and |defined_input.containers[1].volume_ids[0]|
                         (= |input.containers[1].volume_ids[0]|
                            |input.volumes[1].id|))
                    (and |defined_input.containers[1].volume_ids[1]|
                         (= |input.containers[1].volume_ids[1]|
                            |input.volumes[1].id|)))
                (and |defined_input.volumes[1].encrypted|
                     (= |input.volumes[1].encrypted| false))
                |defined_input.containers[1]|))
      (a!9 (and (and true |defined_input.containers[1]|)
                |defined_input.volumes[2]|
                |defined_input.containers[1].volume_ids|
                |defined_input.volumes[2].id|
                (or (and |defined_input.containers[1].volume_ids[0]|
                         (= |input.containers[1].volume_ids[0]|
                            |input.volumes[2].id|))
                    (and |defined_input.containers[1].volume_ids[1]|
                         (= |input.containers[1].volume_ids[1]|
                            |input.volumes[2].id|)))
                (and |defined_input.volumes[2].encrypted|
                     (= |input.volumes[2].encrypted| false))
                |defined_input.containers[1]|)))
  (>= (+ 0
         (ite (or a!1 a!2 a!3) 1 0)
         (ite (or a!4 a!5 a!6) 1 0)
         (ite (or a!7 a!8 a!9) 1 0))
      0)))
(assert (let ((a!1 (and true
                (and true |defined_input.containers[0]|)
                |defined_input.volumes[0]|
                |defined_input.containers[0].volume_ids|
                |defined_input.volumes[0].id|
                (or (and |defined_input.containers[0].volume_ids[1]|
                         (= |input.containers[0].volume_ids[1]|
                            |input.volumes[0].id|))
                    (and |defined_input.containers[0].volume_ids[0]|
                         (= |input.containers[0].volume_ids[0]|
                            |input.volumes[0].id|)))
                (and |defined_input.volumes[0].encrypted|
                     (= |input.volumes[0].encrypted| false))
                |defined_input.containers[0]|
                |defined_input.containers[0]|))
      (a!2 (and true
                (and true |defined_input.containers[0]|)
                |defined_input.volumes[1]|
                |defined_input.containers[0].volume_ids|
                |defined_input.volumes[1].id|
                (or (and |defined_input.containers[0].volume_ids[1]|
                         (= |input.containers[0].volume_ids[1]|
                            |input.volumes[1].id|))
                    (and |defined_input.containers[0].volume_ids[0]|
                         (= |input.containers[0].volume_ids[0]|
                            |input.volumes[1].id|)))
                (and |defined_input.volumes[1].encrypted|
                     (= |input.volumes[1].encrypted| false))
                |defined_input.containers[0]|
                |defined_input.containers[0]|))
      (a!3 (and true
                (and true |defined_input.containers[0]|)
                |defined_input.volumes[2]|
                |defined_input.containers[0].volume_ids|
                |defined_input.volumes[2].id|
                (or (and |defined_input.containers[0].volume_ids[1]|
                         (= |input.containers[0].volume_ids[1]|
                            |input.volumes[2].id|))
                    (and |defined_input.containers[0].volume_ids[0]|
                         (= |input.containers[0].volume_ids[0]|
                            |input.volumes[2].id|)))
                (and |defined_input.volumes[2].encrypted|
                     (= |input.volumes[2].encrypted| false))
                |defined_input.containers[0]|
                |defined_input.containers[0]|))
      (a!5 (and true
                (and true |defined_input.containers[1]|)
                |defined_input.volumes[0]|
                |defined_input.containers[1].volume_ids|
                |defined_input.volumes[0].id|
                (or (and |defined_input.containers[1].volume_ids[0]|
                         (= |input.containers[1].volume_ids[0]|
                            |input.volumes[0].id|))
                    (and |defined_input.containers[1].volume_ids[1]|
                         (= |input.containers[1].volume_ids[1]|
                            |input.volumes[0].id|)))
                (and |defined_input.volumes[0].encrypted|
                     (= |input.volumes[0].encrypted| false))
                |defined_input.containers[1]|
                |defined_input.containers[1]|))
      (a!6 (and true
                (and true |defined_input.containers[1]|)
                |defined_input.volumes[1]|
                |defined_input.containers[1].volume_ids|
                |defined_input.volumes[1].id|
                (or (and |defined_input.containers[1].volume_ids[0]|
                         (= |input.containers[1].volume_ids[0]|
                            |input.volumes[1].id|))
                    (and |defined_input.containers[1].volume_ids[1]|
                         (= |input.containers[1].volume_ids[1]|
                            |input.volumes[1].id|)))
                (and |defined_input.volumes[1].encrypted|
                     (= |input.volumes[1].encrypted| false))
                |defined_input.containers[1]|
                |defined_input.containers[1]|))
      (a!7 (and true
                (and true |defined_input.containers[1]|)
                |defined_input.volumes[2]|
                |defined_input.containers[1].volume_ids|
                |defined_input.volumes[2].id|
                (or (and |defined_input.containers[1].volume_ids[0]|
                         (= |input.containers[1].volume_ids[0]|
                            |input.volumes[2].id|))
                    (and |defined_input.containers[1].volume_ids[1]|
                         (= |input.containers[1].volume_ids[1]|
                            |input.volumes[2].id|)))
                (and |defined_input.volumes[2].encrypted|
                     (= |input.volumes[2].encrypted| false))
                |defined_input.containers[1]|
                |defined_input.containers[1]|)))
(let ((a!4 (or (and (and true |defined_input.containers[0]|)
                    |defined_input.containers[0].privileged|
                    (= |input.containers[0].privileged| true)
                    |defined_input.containers[0].name|)
               (and a!1
                    |defined_input.hosts[0]|
                    (and |defined_input.hosts[0].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[0].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[0].public|
                         (= |input.hosts[0].public| true))
                    |defined_input.containers[0].name|)
               (and a!1
                    |defined_input.hosts[1]|
                    (and |defined_input.hosts[1].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[1].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[1].public|
                         (= |input.hosts[1].public| true))
                    |defined_input.containers[0].name|)
               (and a!1
                    |defined_input.hosts[2]|
                    (and |defined_input.hosts[2].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[2].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[2].public|
                         (= |input.hosts[2].public| true))
                    |defined_input.containers[0].name|)
               (and a!2
                    |defined_input.hosts[0]|
                    (and |defined_input.hosts[0].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[0].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[0].public|
                         (= |input.hosts[0].public| true))
                    |defined_input.containers[0].name|)
               (and a!2
                    |defined_input.hosts[1]|
                    (and |defined_input.hosts[1].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[1].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[1].public|
                         (= |input.hosts[1].public| true))
                    |defined_input.containers[0].name|)
               (and a!2
                    |defined_input.hosts[2]|
                    (and |defined_input.hosts[2].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[2].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[2].public|
                         (= |input.hosts[2].public| true))
                    |defined_input.containers[0].name|)
               (and a!3
                    |defined_input.hosts[0]|
                    (and |defined_input.hosts[0].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[0].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[0].public|
                         (= |input.hosts[0].public| true))
                    |defined_input.containers[0].name|)
               (and a!3
                    |defined_input.hosts[1]|
                    (and |defined_input.hosts[1].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[1].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[1].public|
                         (= |input.hosts[1].public| true))
                    |defined_input.containers[0].name|)
               (and a!3
                    |defined_input.hosts[2]|
                    (and |defined_input.hosts[2].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[2].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[2].public|
                         (= |input.hosts[2].public| true))
                    |defined_input.containers[0].name|)))
      (a!8 (or (and (and true |defined_input.containers[1]|)
                    |defined_input.containers[1].privileged|
                    (= |input.containers[1].privileged| true)
                    |defined_input.containers[1].name|)
               (and a!5
                    |defined_input.hosts[0]|
                    (and |defined_input.hosts[0].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[0].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[0].public|
                         (= |input.hosts[0].public| true))
                    |defined_input.containers[1].name|)
               (and a!5
                    |defined_input.hosts[1]|
                    (and |defined_input.hosts[1].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[1].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[1].public|
                         (= |input.hosts[1].public| true))
                    |defined_input.containers[1].name|)
               (and a!5
                    |defined_input.hosts[2]|
                    (and |defined_input.hosts[2].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[2].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[2].public|
                         (= |input.hosts[2].public| true))
                    |defined_input.containers[1].name|)
               (and a!6
                    |defined_input.hosts[0]|
                    (and |defined_input.hosts[0].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[0].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[0].public|
                         (= |input.hosts[0].public| true))
                    |defined_input.containers[1].name|)
               (and a!6
                    |defined_input.hosts[1]|
                    (and |defined_input.hosts[1].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[1].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[1].public|
                         (= |input.hosts[1].public| true))
                    |defined_input.containers[1].name|)
               (and a!6
                    |defined_input.hosts[2]|
                    (and |defined_input.hosts[2].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[2].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[2].public|
                         (= |input.hosts[2].public| true))
                    |defined_input.containers[1].name|)
               (and a!7
                    |defined_input.hosts[0]|
                    (and |defined_input.hosts[0].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[0].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[0].public|
                         (= |input.hosts[0].public| true))
                    |defined_input.containers[1].name|)
               (and a!7
                    |defined_input.hosts[1]|
                    (and |defined_input.hosts[1].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[1].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[1].public|
                         (= |input.hosts[1].public| true))
                    |defined_input.containers[1].name|)
               (and a!7
                    |defined_input.hosts[2]|
                    (and |defined_input.hosts[2].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[2].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[2].public|
                         (= |input.hosts[2].public| true))
                    |defined_input.containers[1].name|))))
  (=> (and a!4 a!8)
      (not (= |input.containers[0].name| |input.containers[1].name|))))))
(assert (let ((a!1 (and true
                (and true |defined_input.containers[0]|)
                |defined_input.volumes[0]|
                |defined_input.containers[0].volume_ids|
                |defined_input.volumes[0].id|
                (or (and |defined_input.containers[0].volume_ids[1]|
                         (= |input.containers[0].volume_ids[1]|
                            |input.volumes[0].id|))
                    (and |defined_input.containers[0].volume_ids[0]|
                         (= |input.containers[0].volume_ids[0]|
                            |input.volumes[0].id|)))
                (and |defined_input.volumes[0].encrypted|
                     (= |input.volumes[0].encrypted| false))
                |defined_input.containers[0]|
                |defined_input.containers[0]|))
      (a!2 (and true
                (and true |defined_input.containers[0]|)
                |defined_input.volumes[1]|
                |defined_input.containers[0].volume_ids|
                |defined_input.volumes[1].id|
                (or (and |defined_input.containers[0].volume_ids[1]|
                         (= |input.containers[0].volume_ids[1]|
                            |input.volumes[1].id|))
                    (and |defined_input.containers[0].volume_ids[0]|
                         (= |input.containers[0].volume_ids[0]|
                            |input.volumes[1].id|)))
                (and |defined_input.volumes[1].encrypted|
                     (= |input.volumes[1].encrypted| false))
                |defined_input.containers[0]|
                |defined_input.containers[0]|))
      (a!3 (and true
                (and true |defined_input.containers[0]|)
                |defined_input.volumes[2]|
                |defined_input.containers[0].volume_ids|
                |defined_input.volumes[2].id|
                (or (and |defined_input.containers[0].volume_ids[1]|
                         (= |input.containers[0].volume_ids[1]|
                            |input.volumes[2].id|))
                    (and |defined_input.containers[0].volume_ids[0]|
                         (= |input.containers[0].volume_ids[0]|
                            |input.volumes[2].id|)))
                (and |defined_input.volumes[2].encrypted|
                     (= |input.volumes[2].encrypted| false))
                |defined_input.containers[0]|
                |defined_input.containers[0]|))
      (a!5 (and true
                (and true |defined_input.containers[2]|)
                |defined_input.volumes[0]|
                |defined_input.containers[2].volume_ids|
                |defined_input.volumes[0].id|
                (or (and |defined_input.containers[2].volume_ids[1]|
                         (= |input.containers[2].volume_ids[1]|
                            |input.volumes[0].id|))
                    (and |defined_input.containers[2].volume_ids[0]|
                         (= |input.containers[2].volume_ids[0]|
                            |input.volumes[0].id|)))
                (and |defined_input.volumes[0].encrypted|
                     (= |input.volumes[0].encrypted| false))
                |defined_input.containers[2]|
                |defined_input.containers[2]|))
      (a!6 (and true
                (and true |defined_input.containers[2]|)
                |defined_input.volumes[1]|
                |defined_input.containers[2].volume_ids|
                |defined_input.volumes[1].id|
                (or (and |defined_input.containers[2].volume_ids[1]|
                         (= |input.containers[2].volume_ids[1]|
                            |input.volumes[1].id|))
                    (and |defined_input.containers[2].volume_ids[0]|
                         (= |input.containers[2].volume_ids[0]|
                            |input.volumes[1].id|)))
                (and |defined_input.volumes[1].encrypted|
                     (= |input.volumes[1].encrypted| false))
                |defined_input.containers[2]|
                |defined_input.containers[2]|))
      (a!7 (and true
                (and true |defined_input.containers[2]|)
                |defined_input.volumes[2]|
                |defined_input.containers[2].volume_ids|
                |defined_input.volumes[2].id|
                (or (and |defined_input.containers[2].volume_ids[1]|
                         (= |input.containers[2].volume_ids[1]|
                            |input.volumes[2].id|))
                    (and |defined_input.containers[2].volume_ids[0]|
                         (= |input.containers[2].volume_ids[0]|
                            |input.volumes[2].id|)))
                (and |defined_input.volumes[2].encrypted|
                     (= |input.volumes[2].encrypted| false))
                |defined_input.containers[2]|
                |defined_input.containers[2]|)))
(let ((a!4 (or (and (and true |defined_input.containers[0]|)
                    |defined_input.containers[0].privileged|
                    (= |input.containers[0].privileged| true)
                    |defined_input.containers[0].name|)
               (and a!1
                    |defined_input.hosts[0]|
                    (and |defined_input.hosts[0].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[0].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[0].public|
                         (= |input.hosts[0].public| true))
                    |defined_input.containers[0].name|)
               (and a!1
                    |defined_input.hosts[1]|
                    (and |defined_input.hosts[1].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[1].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[1].public|
                         (= |input.hosts[1].public| true))
                    |defined_input.containers[0].name|)
               (and a!1
                    |defined_input.hosts[2]|
                    (and |defined_input.hosts[2].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[2].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[2].public|
                         (= |input.hosts[2].public| true))
                    |defined_input.containers[0].name|)
               (and a!2
                    |defined_input.hosts[0]|
                    (and |defined_input.hosts[0].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[0].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[0].public|
                         (= |input.hosts[0].public| true))
                    |defined_input.containers[0].name|)
               (and a!2
                    |defined_input.hosts[1]|
                    (and |defined_input.hosts[1].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[1].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[1].public|
                         (= |input.hosts[1].public| true))
                    |defined_input.containers[0].name|)
               (and a!2
                    |defined_input.hosts[2]|
                    (and |defined_input.hosts[2].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[2].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[2].public|
                         (= |input.hosts[2].public| true))
                    |defined_input.containers[0].name|)
               (and a!3
                    |defined_input.hosts[0]|
                    (and |defined_input.hosts[0].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[0].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[0].public|
                         (= |input.hosts[0].public| true))
                    |defined_input.containers[0].name|)
               (and a!3
                    |defined_input.hosts[1]|
                    (and |defined_input.hosts[1].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[1].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[1].public|
                         (= |input.hosts[1].public| true))
                    |defined_input.containers[0].name|)
               (and a!3
                    |defined_input.hosts[2]|
                    (and |defined_input.hosts[2].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[2].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[2].public|
                         (= |input.hosts[2].public| true))
                    |defined_input.containers[0].name|)))
      (a!8 (or (and (and true |defined_input.containers[2]|)
                    |defined_input.containers[2].privileged|
                    (= |input.containers[2].privileged| true)
                    |defined_input.containers[2].name|)
               (and a!5
                    |defined_input.hosts[0]|
                    (and |defined_input.hosts[0].id|
                         |defined_input.containers[2].host_id|
                         (= |input.hosts[0].id| |input.containers[2].host_id|))
                    (and |defined_input.hosts[0].public|
                         (= |input.hosts[0].public| true))
                    |defined_input.containers[2].name|)
               (and a!5
                    |defined_input.hosts[1]|
                    (and |defined_input.hosts[1].id|
                         |defined_input.containers[2].host_id|
                         (= |input.hosts[1].id| |input.containers[2].host_id|))
                    (and |defined_input.hosts[1].public|
                         (= |input.hosts[1].public| true))
                    |defined_input.containers[2].name|)
               (and a!5
                    |defined_input.hosts[2]|
                    (and |defined_input.hosts[2].id|
                         |defined_input.containers[2].host_id|
                         (= |input.hosts[2].id| |input.containers[2].host_id|))
                    (and |defined_input.hosts[2].public|
                         (= |input.hosts[2].public| true))
                    |defined_input.containers[2].name|)
               (and a!6
                    |defined_input.hosts[0]|
                    (and |defined_input.hosts[0].id|
                         |defined_input.containers[2].host_id|
                         (= |input.hosts[0].id| |input.containers[2].host_id|))
                    (and |defined_input.hosts[0].public|
                         (= |input.hosts[0].public| true))
                    |defined_input.containers[2].name|)
               (and a!6
                    |defined_input.hosts[1]|
                    (and |defined_input.hosts[1].id|
                         |defined_input.containers[2].host_id|
                         (= |input.hosts[1].id| |input.containers[2].host_id|))
                    (and |defined_input.hosts[1].public|
                         (= |input.hosts[1].public| true))
                    |defined_input.containers[2].name|)
               (and a!6
                    |defined_input.hosts[2]|
                    (and |defined_input.hosts[2].id|
                         |defined_input.containers[2].host_id|
                         (= |input.hosts[2].id| |input.containers[2].host_id|))
                    (and |defined_input.hosts[2].public|
                         (= |input.hosts[2].public| true))
                    |defined_input.containers[2].name|)
               (and a!7
                    |defined_input.hosts[0]|
                    (and |defined_input.hosts[0].id|
                         |defined_input.containers[2].host_id|
                         (= |input.hosts[0].id| |input.containers[2].host_id|))
                    (and |defined_input.hosts[0].public|
                         (= |input.hosts[0].public| true))
                    |defined_input.containers[2].name|)
               (and a!7
                    |defined_input.hosts[1]|
                    (and |defined_input.hosts[1].id|
                         |defined_input.containers[2].host_id|
                         (= |input.hosts[1].id| |input.containers[2].host_id|))
                    (and |defined_input.hosts[1].public|
                         (= |input.hosts[1].public| true))
                    |defined_input.containers[2].name|)
               (and a!7
                    |defined_input.hosts[2]|
                    (and |defined_input.hosts[2].id|
                         |defined_input.containers[2].host_id|
                         (= |input.hosts[2].id| |input.containers[2].host_id|))
                    (and |defined_input.hosts[2].public|
                         (= |input.hosts[2].public| true))
                    |defined_input.containers[2].name|))))
  (=> (and a!4 a!8)
      (not (= |input.containers[0].name| |input.containers[2].name|))))))
(assert (let ((a!1 (and true
                (and true |defined_input.containers[1]|)
                |defined_input.volumes[0]|
                |defined_input.containers[1].volume_ids|
                |defined_input.volumes[0].id|
                (or (and |defined_input.containers[1].volume_ids[0]|
                         (= |input.containers[1].volume_ids[0]|
                            |input.volumes[0].id|))
                    (and |defined_input.containers[1].volume_ids[1]|
                         (= |input.containers[1].volume_ids[1]|
                            |input.volumes[0].id|)))
                (and |defined_input.volumes[0].encrypted|
                     (= |input.volumes[0].encrypted| false))
                |defined_input.containers[1]|
                |defined_input.containers[1]|))
      (a!2 (and true
                (and true |defined_input.containers[1]|)
                |defined_input.volumes[1]|
                |defined_input.containers[1].volume_ids|
                |defined_input.volumes[1].id|
                (or (and |defined_input.containers[1].volume_ids[0]|
                         (= |input.containers[1].volume_ids[0]|
                            |input.volumes[1].id|))
                    (and |defined_input.containers[1].volume_ids[1]|
                         (= |input.containers[1].volume_ids[1]|
                            |input.volumes[1].id|)))
                (and |defined_input.volumes[1].encrypted|
                     (= |input.volumes[1].encrypted| false))
                |defined_input.containers[1]|
                |defined_input.containers[1]|))
      (a!3 (and true
                (and true |defined_input.containers[1]|)
                |defined_input.volumes[2]|
                |defined_input.containers[1].volume_ids|
                |defined_input.volumes[2].id|
                (or (and |defined_input.containers[1].volume_ids[0]|
                         (= |input.containers[1].volume_ids[0]|
                            |input.volumes[2].id|))
                    (and |defined_input.containers[1].volume_ids[1]|
                         (= |input.containers[1].volume_ids[1]|
                            |input.volumes[2].id|)))
                (and |defined_input.volumes[2].encrypted|
                     (= |input.volumes[2].encrypted| false))
                |defined_input.containers[1]|
                |defined_input.containers[1]|))
      (a!5 (and true
                (and true |defined_input.containers[2]|)
                |defined_input.volumes[0]|
                |defined_input.containers[2].volume_ids|
                |defined_input.volumes[0].id|
                (or (and |defined_input.containers[2].volume_ids[1]|
                         (= |input.containers[2].volume_ids[1]|
                            |input.volumes[0].id|))
                    (and |defined_input.containers[2].volume_ids[0]|
                         (= |input.containers[2].volume_ids[0]|
                            |input.volumes[0].id|)))
                (and |defined_input.volumes[0].encrypted|
                     (= |input.volumes[0].encrypted| false))
                |defined_input.containers[2]|
                |defined_input.containers[2]|))
      (a!6 (and true
                (and true |defined_input.containers[2]|)
                |defined_input.volumes[1]|
                |defined_input.containers[2].volume_ids|
                |defined_input.volumes[1].id|
                (or (and |defined_input.containers[2].volume_ids[1]|
                         (= |input.containers[2].volume_ids[1]|
                            |input.volumes[1].id|))
                    (and |defined_input.containers[2].volume_ids[0]|
                         (= |input.containers[2].volume_ids[0]|
                            |input.volumes[1].id|)))
                (and |defined_input.volumes[1].encrypted|
                     (= |input.volumes[1].encrypted| false))
                |defined_input.containers[2]|
                |defined_input.containers[2]|))
      (a!7 (and true
                (and true |defined_input.containers[2]|)
                |defined_input.volumes[2]|
                |defined_input.containers[2].volume_ids|
                |defined_input.volumes[2].id|
                (or (and |defined_input.containers[2].volume_ids[1]|
                         (= |input.containers[2].volume_ids[1]|
                            |input.volumes[2].id|))
                    (and |defined_input.containers[2].volume_ids[0]|
                         (= |input.containers[2].volume_ids[0]|
                            |input.volumes[2].id|)))
                (and |defined_input.volumes[2].encrypted|
                     (= |input.volumes[2].encrypted| false))
                |defined_input.containers[2]|
                |defined_input.containers[2]|)))
(let ((a!4 (or (and (and true |defined_input.containers[1]|)
                    |defined_input.containers[1].privileged|
                    (= |input.containers[1].privileged| true)
                    |defined_input.containers[1].name|)
               (and a!1
                    |defined_input.hosts[0]|
                    (and |defined_input.hosts[0].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[0].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[0].public|
                         (= |input.hosts[0].public| true))
                    |defined_input.containers[1].name|)
               (and a!1
                    |defined_input.hosts[1]|
                    (and |defined_input.hosts[1].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[1].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[1].public|
                         (= |input.hosts[1].public| true))
                    |defined_input.containers[1].name|)
               (and a!1
                    |defined_input.hosts[2]|
                    (and |defined_input.hosts[2].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[2].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[2].public|
                         (= |input.hosts[2].public| true))
                    |defined_input.containers[1].name|)
               (and a!2
                    |defined_input.hosts[0]|
                    (and |defined_input.hosts[0].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[0].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[0].public|
                         (= |input.hosts[0].public| true))
                    |defined_input.containers[1].name|)
               (and a!2
                    |defined_input.hosts[1]|
                    (and |defined_input.hosts[1].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[1].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[1].public|
                         (= |input.hosts[1].public| true))
                    |defined_input.containers[1].name|)
               (and a!2
                    |defined_input.hosts[2]|
                    (and |defined_input.hosts[2].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[2].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[2].public|
                         (= |input.hosts[2].public| true))
                    |defined_input.containers[1].name|)
               (and a!3
                    |defined_input.hosts[0]|
                    (and |defined_input.hosts[0].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[0].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[0].public|
                         (= |input.hosts[0].public| true))
                    |defined_input.containers[1].name|)
               (and a!3
                    |defined_input.hosts[1]|
                    (and |defined_input.hosts[1].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[1].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[1].public|
                         (= |input.hosts[1].public| true))
                    |defined_input.containers[1].name|)
               (and a!3
                    |defined_input.hosts[2]|
                    (and |defined_input.hosts[2].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[2].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[2].public|
                         (= |input.hosts[2].public| true))
                    |defined_input.containers[1].name|)))
      (a!8 (or (and (and true |defined_input.containers[2]|)
                    |defined_input.containers[2].privileged|
                    (= |input.containers[2].privileged| true)
                    |defined_input.containers[2].name|)
               (and a!5
                    |defined_input.hosts[0]|
                    (and |defined_input.hosts[0].id|
                         |defined_input.containers[2].host_id|
                         (= |input.hosts[0].id| |input.containers[2].host_id|))
                    (and |defined_input.hosts[0].public|
                         (= |input.hosts[0].public| true))
                    |defined_input.containers[2].name|)
               (and a!5
                    |defined_input.hosts[1]|
                    (and |defined_input.hosts[1].id|
                         |defined_input.containers[2].host_id|
                         (= |input.hosts[1].id| |input.containers[2].host_id|))
                    (and |defined_input.hosts[1].public|
                         (= |input.hosts[1].public| true))
                    |defined_input.containers[2].name|)
               (and a!5
                    |defined_input.hosts[2]|
                    (and |defined_input.hosts[2].id|
                         |defined_input.containers[2].host_id|
                         (= |input.hosts[2].id| |input.containers[2].host_id|))
                    (and |defined_input.hosts[2].public|
                         (= |input.hosts[2].public| true))
                    |defined_input.containers[2].name|)
               (and a!6
                    |defined_input.hosts[0]|
                    (and |defined_input.hosts[0].id|
                         |defined_input.containers[2].host_id|
                         (= |input.hosts[0].id| |input.containers[2].host_id|))
                    (and |defined_input.hosts[0].public|
                         (= |input.hosts[0].public| true))
                    |defined_input.containers[2].name|)
               (and a!6
                    |defined_input.hosts[1]|
                    (and |defined_input.hosts[1].id|
                         |defined_input.containers[2].host_id|
                         (= |input.hosts[1].id| |input.containers[2].host_id|))
                    (and |defined_input.hosts[1].public|
                         (= |input.hosts[1].public| true))
                    |defined_input.containers[2].name|)
               (and a!6
                    |defined_input.hosts[2]|
                    (and |defined_input.hosts[2].id|
                         |defined_input.containers[2].host_id|
                         (= |input.hosts[2].id| |input.containers[2].host_id|))
                    (and |defined_input.hosts[2].public|
                         (= |input.hosts[2].public| true))
                    |defined_input.containers[2].name|)
               (and a!7
                    |defined_input.hosts[0]|
                    (and |defined_input.hosts[0].id|
                         |defined_input.containers[2].host_id|
                         (= |input.hosts[0].id| |input.containers[2].host_id|))
                    (and |defined_input.hosts[0].public|
                         (= |input.hosts[0].public| true))
                    |defined_input.containers[2].name|)
               (and a!7
                    |defined_input.hosts[1]|
                    (and |defined_input.hosts[1].id|
                         |defined_input.containers[2].host_id|
                         (= |input.hosts[1].id| |input.containers[2].host_id|))
                    (and |defined_input.hosts[1].public|
                         (= |input.hosts[1].public| true))
                    |defined_input.containers[2].name|)
               (and a!7
                    |defined_input.hosts[2]|
                    (and |defined_input.hosts[2].id|
                         |defined_input.containers[2].host_id|
                         (= |input.hosts[2].id| |input.containers[2].host_id|))
                    (and |defined_input.hosts[2].public|
                         (= |input.hosts[2].public| true))
                    |defined_input.containers[2].name|))))
  (=> (and a!4 a!8)
      (not (= |input.containers[1].name| |input.containers[2].name|))))))
(assert (let ((a!1 (and true
                (and true |defined_input.containers[0]|)
                |defined_input.volumes[0]|
                |defined_input.containers[0].volume_ids|
                |defined_input.volumes[0].id|
                (or (and |defined_input.containers[0].volume_ids[1]|
                         (= |input.containers[0].volume_ids[1]|
                            |input.volumes[0].id|))
                    (and |defined_input.containers[0].volume_ids[0]|
                         (= |input.containers[0].volume_ids[0]|
                            |input.volumes[0].id|)))
                (and |defined_input.volumes[0].encrypted|
                     (= |input.volumes[0].encrypted| false))
                |defined_input.containers[0]|
                |defined_input.containers[0]|))
      (a!2 (and true
                (and true |defined_input.containers[0]|)
                |defined_input.volumes[1]|
                |defined_input.containers[0].volume_ids|
                |defined_input.volumes[1].id|
                (or (and |defined_input.containers[0].volume_ids[1]|
                         (= |input.containers[0].volume_ids[1]|
                            |input.volumes[1].id|))
                    (and |defined_input.containers[0].volume_ids[0]|
                         (= |input.containers[0].volume_ids[0]|
                            |input.volumes[1].id|)))
                (and |defined_input.volumes[1].encrypted|
                     (= |input.volumes[1].encrypted| false))
                |defined_input.containers[0]|
                |defined_input.containers[0]|))
      (a!3 (and true
                (and true |defined_input.containers[0]|)
                |defined_input.volumes[2]|
                |defined_input.containers[0].volume_ids|
                |defined_input.volumes[2].id|
                (or (and |defined_input.containers[0].volume_ids[1]|
                         (= |input.containers[0].volume_ids[1]|
                            |input.volumes[2].id|))
                    (and |defined_input.containers[0].volume_ids[0]|
                         (= |input.containers[0].volume_ids[0]|
                            |input.volumes[2].id|)))
                (and |defined_input.volumes[2].encrypted|
                     (= |input.volumes[2].encrypted| false))
                |defined_input.containers[0]|
                |defined_input.containers[0]|))
      (a!5 (and true
                (and true |defined_input.containers[1]|)
                |defined_input.volumes[0]|
                |defined_input.containers[1].volume_ids|
                |defined_input.volumes[0].id|
                (or (and |defined_input.containers[1].volume_ids[0]|
                         (= |input.containers[1].volume_ids[0]|
                            |input.volumes[0].id|))
                    (and |defined_input.containers[1].volume_ids[1]|
                         (= |input.containers[1].volume_ids[1]|
                            |input.volumes[0].id|)))
                (and |defined_input.volumes[0].encrypted|
                     (= |input.volumes[0].encrypted| false))
                |defined_input.containers[1]|
                |defined_input.containers[1]|))
      (a!6 (and true
                (and true |defined_input.containers[1]|)
                |defined_input.volumes[1]|
                |defined_input.containers[1].volume_ids|
                |defined_input.volumes[1].id|
                (or (and |defined_input.containers[1].volume_ids[0]|
                         (= |input.containers[1].volume_ids[0]|
                            |input.volumes[1].id|))
                    (and |defined_input.containers[1].volume_ids[1]|
                         (= |input.containers[1].volume_ids[1]|
                            |input.volumes[1].id|)))
                (and |defined_input.volumes[1].encrypted|
                     (= |input.volumes[1].encrypted| false))
                |defined_input.containers[1]|
                |defined_input.containers[1]|))
      (a!7 (and true
                (and true |defined_input.containers[1]|)
                |defined_input.volumes[2]|
                |defined_input.containers[1].volume_ids|
                |defined_input.volumes[2].id|
                (or (and |defined_input.containers[1].volume_ids[0]|
                         (= |input.containers[1].volume_ids[0]|
                            |input.volumes[2].id|))
                    (and |defined_input.containers[1].volume_ids[1]|
                         (= |input.containers[1].volume_ids[1]|
                            |input.volumes[2].id|)))
                (and |defined_input.volumes[2].encrypted|
                     (= |input.volumes[2].encrypted| false))
                |defined_input.containers[1]|
                |defined_input.containers[1]|))
      (a!9 (and true
                (and true |defined_input.containers[2]|)
                |defined_input.volumes[0]|
                |defined_input.containers[2].volume_ids|
                |defined_input.volumes[0].id|
                (or (and |defined_input.containers[2].volume_ids[1]|
                         (= |input.containers[2].volume_ids[1]|
                            |input.volumes[0].id|))
                    (and |defined_input.containers[2].volume_ids[0]|
                         (= |input.containers[2].volume_ids[0]|
                            |input.volumes[0].id|)))
                (and |defined_input.volumes[0].encrypted|
                     (= |input.volumes[0].encrypted| false))
                |defined_input.containers[2]|
                |defined_input.containers[2]|))
      (a!10 (and true
                 (and true |defined_input.containers[2]|)
                 |defined_input.volumes[1]|
                 |defined_input.containers[2].volume_ids|
                 |defined_input.volumes[1].id|
                 (or (and |defined_input.containers[2].volume_ids[1]|
                          (= |input.containers[2].volume_ids[1]|
                             |input.volumes[1].id|))
                     (and |defined_input.containers[2].volume_ids[0]|
                          (= |input.containers[2].volume_ids[0]|
                             |input.volumes[1].id|)))
                 (and |defined_input.volumes[1].encrypted|
                      (= |input.volumes[1].encrypted| false))
                 |defined_input.containers[2]|
                 |defined_input.containers[2]|))
      (a!11 (and true
                 (and true |defined_input.containers[2]|)
                 |defined_input.volumes[2]|
                 |defined_input.containers[2].volume_ids|
                 |defined_input.volumes[2].id|
                 (or (and |defined_input.containers[2].volume_ids[1]|
                          (= |input.containers[2].volume_ids[1]|
                             |input.volumes[2].id|))
                     (and |defined_input.containers[2].volume_ids[0]|
                          (= |input.containers[2].volume_ids[0]|
                             |input.volumes[2].id|)))
                 (and |defined_input.volumes[2].encrypted|
                      (= |input.volumes[2].encrypted| false))
                 |defined_input.containers[2]|
                 |defined_input.containers[2]|)))
(let ((a!4 (or (and (and true |defined_input.containers[0]|)
                    |defined_input.containers[0].privileged|
                    (= |input.containers[0].privileged| true)
                    |defined_input.containers[0].name|)
               (and a!1
                    |defined_input.hosts[0]|
                    (and |defined_input.hosts[0].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[0].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[0].public|
                         (= |input.hosts[0].public| true))
                    |defined_input.containers[0].name|)
               (and a!1
                    |defined_input.hosts[1]|
                    (and |defined_input.hosts[1].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[1].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[1].public|
                         (= |input.hosts[1].public| true))
                    |defined_input.containers[0].name|)
               (and a!1
                    |defined_input.hosts[2]|
                    (and |defined_input.hosts[2].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[2].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[2].public|
                         (= |input.hosts[2].public| true))
                    |defined_input.containers[0].name|)
               (and a!2
                    |defined_input.hosts[0]|
                    (and |defined_input.hosts[0].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[0].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[0].public|
                         (= |input.hosts[0].public| true))
                    |defined_input.containers[0].name|)
               (and a!2
                    |defined_input.hosts[1]|
                    (and |defined_input.hosts[1].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[1].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[1].public|
                         (= |input.hosts[1].public| true))
                    |defined_input.containers[0].name|)
               (and a!2
                    |defined_input.hosts[2]|
                    (and |defined_input.hosts[2].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[2].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[2].public|
                         (= |input.hosts[2].public| true))
                    |defined_input.containers[0].name|)
               (and a!3
                    |defined_input.hosts[0]|
                    (and |defined_input.hosts[0].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[0].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[0].public|
                         (= |input.hosts[0].public| true))
                    |defined_input.containers[0].name|)
               (and a!3
                    |defined_input.hosts[1]|
                    (and |defined_input.hosts[1].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[1].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[1].public|
                         (= |input.hosts[1].public| true))
                    |defined_input.containers[0].name|)
               (and a!3
                    |defined_input.hosts[2]|
                    (and |defined_input.hosts[2].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[2].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[2].public|
                         (= |input.hosts[2].public| true))
                    |defined_input.containers[0].name|)))
      (a!8 (or (and (and true |defined_input.containers[1]|)
                    |defined_input.containers[1].privileged|
                    (= |input.containers[1].privileged| true)
                    |defined_input.containers[1].name|)
               (and a!5
                    |defined_input.hosts[0]|
                    (and |defined_input.hosts[0].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[0].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[0].public|
                         (= |input.hosts[0].public| true))
                    |defined_input.containers[1].name|)
               (and a!5
                    |defined_input.hosts[1]|
                    (and |defined_input.hosts[1].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[1].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[1].public|
                         (= |input.hosts[1].public| true))
                    |defined_input.containers[1].name|)
               (and a!5
                    |defined_input.hosts[2]|
                    (and |defined_input.hosts[2].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[2].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[2].public|
                         (= |input.hosts[2].public| true))
                    |defined_input.containers[1].name|)
               (and a!6
                    |defined_input.hosts[0]|
                    (and |defined_input.hosts[0].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[0].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[0].public|
                         (= |input.hosts[0].public| true))
                    |defined_input.containers[1].name|)
               (and a!6
                    |defined_input.hosts[1]|
                    (and |defined_input.hosts[1].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[1].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[1].public|
                         (= |input.hosts[1].public| true))
                    |defined_input.containers[1].name|)
               (and a!6
                    |defined_input.hosts[2]|
                    (and |defined_input.hosts[2].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[2].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[2].public|
                         (= |input.hosts[2].public| true))
                    |defined_input.containers[1].name|)
               (and a!7
                    |defined_input.hosts[0]|
                    (and |defined_input.hosts[0].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[0].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[0].public|
                         (= |input.hosts[0].public| true))
                    |defined_input.containers[1].name|)
               (and a!7
                    |defined_input.hosts[1]|
                    (and |defined_input.hosts[1].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[1].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[1].public|
                         (= |input.hosts[1].public| true))
                    |defined_input.containers[1].name|)
               (and a!7
                    |defined_input.hosts[2]|
                    (and |defined_input.hosts[2].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[2].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[2].public|
                         (= |input.hosts[2].public| true))
                    |defined_input.containers[1].name|)))
      (a!12 (or (and (and true |defined_input.containers[2]|)
                     |defined_input.containers[2].privileged|
                     (= |input.containers[2].privileged| true)
                     |defined_input.containers[2].name|)
                (and a!9
                     |defined_input.hosts[0]|
                     (and |defined_input.hosts[0].id|
                          |defined_input.containers[2].host_id|
                          (= |input.hosts[0].id| |input.containers[2].host_id|))
                     (and |defined_input.hosts[0].public|
                          (= |input.hosts[0].public| true))
                     |defined_input.containers[2].name|)
                (and a!9
                     |defined_input.hosts[1]|
                     (and |defined_input.hosts[1].id|
                          |defined_input.containers[2].host_id|
                          (= |input.hosts[1].id| |input.containers[2].host_id|))
                     (and |defined_input.hosts[1].public|
                          (= |input.hosts[1].public| true))
                     |defined_input.containers[2].name|)
                (and a!9
                     |defined_input.hosts[2]|
                     (and |defined_input.hosts[2].id|
                          |defined_input.containers[2].host_id|
                          (= |input.hosts[2].id| |input.containers[2].host_id|))
                     (and |defined_input.hosts[2].public|
                          (= |input.hosts[2].public| true))
                     |defined_input.containers[2].name|)
                (and a!10
                     |defined_input.hosts[0]|
                     (and |defined_input.hosts[0].id|
                          |defined_input.containers[2].host_id|
                          (= |input.hosts[0].id| |input.containers[2].host_id|))
                     (and |defined_input.hosts[0].public|
                          (= |input.hosts[0].public| true))
                     |defined_input.containers[2].name|)
                (and a!10
                     |defined_input.hosts[1]|
                     (and |defined_input.hosts[1].id|
                          |defined_input.containers[2].host_id|
                          (= |input.hosts[1].id| |input.containers[2].host_id|))
                     (and |defined_input.hosts[1].public|
                          (= |input.hosts[1].public| true))
                     |defined_input.containers[2].name|)
                (and a!10
                     |defined_input.hosts[2]|
                     (and |defined_input.hosts[2].id|
                          |defined_input.containers[2].host_id|
                          (= |input.hosts[2].id| |input.containers[2].host_id|))
                     (and |defined_input.hosts[2].public|
                          (= |input.hosts[2].public| true))
                     |defined_input.containers[2].name|)
                (and a!11
                     |defined_input.hosts[0]|
                     (and |defined_input.hosts[0].id|
                          |defined_input.containers[2].host_id|
                          (= |input.hosts[0].id| |input.containers[2].host_id|))
                     (and |defined_input.hosts[0].public|
                          (= |input.hosts[0].public| true))
                     |defined_input.containers[2].name|)
                (and a!11
                     |defined_input.hosts[1]|
                     (and |defined_input.hosts[1].id|
                          |defined_input.containers[2].host_id|
                          (= |input.hosts[1].id| |input.containers[2].host_id|))
                     (and |defined_input.hosts[1].public|
                          (= |input.hosts[1].public| true))
                     |defined_input.containers[2].name|)
                (and a!11
                     |defined_input.hosts[2]|
                     (and |defined_input.hosts[2].id|
                          |defined_input.containers[2].host_id|
                          (= |input.hosts[2].id| |input.containers[2].host_id|))
                     (and |defined_input.hosts[2].public|
                          (= |input.hosts[2].public| true))
                     |defined_input.containers[2].name|))))
  (>= (+ 0 (ite a!4 1 0) (ite a!8 1 0) (ite a!12 1 0)) 0))))
(assert (or (= |input.containers[0].host_id| "host1")
    (= |input.containers[0].host_id| "host2")
    (= |input.containers[0].host_id| "host3")))
(assert (or (= |input.containers[0].name| "web")
    (= |input.containers[0].name| "api")
    (= |input.containers[0].name| "worker")))
(assert (or (= |input.containers[0].volume_ids[0]| "vol1")
    (= |input.containers[0].volume_ids[0]| "vol2")
    (= |input.containers[0].volume_ids[0]| "vol3")))
(assert (or (= |input.containers[0].volume_ids[1]| "vol1")
    (= |input.containers[0].volume_ids[1]| "vol2")
    (= |input.containers[0].volume_ids[1]| "vol3")))
(assert |defined_input.containers[0].volume_ids[0]|)
(assert (=> (and |defined_input.containers[0].volume_ids[0]|
         |defined_input.containers[0].volume_ids[1]|)
    (not (= |input.containers[0].volume_ids[0]|
            |input.containers[0].volume_ids[1]|))))
(assert |defined_input.containers[0].name|)
(assert |defined_input.containers[0].privileged|)
(assert |defined_input.containers[0].host_id|)
(assert |defined_input.containers[0].volume_ids|)
(assert (or (= |input.containers[1].host_id| "host1")
    (= |input.containers[1].host_id| "host2")
    (= |input.containers[1].host_id| "host3")))
(assert (or (= |input.containers[1].name| "web")
    (= |input.containers[1].name| "api")
    (= |input.containers[1].name| "worker")))
(assert (or (= |input.containers[1].volume_ids[0]| "vol1")
    (= |input.containers[1].volume_ids[0]| "vol2")
    (= |input.containers[1].volume_ids[0]| "vol3")))
(assert (or (= |input.containers[1].volume_ids[1]| "vol1")
    (= |input.containers[1].volume_ids[1]| "vol2")
    (= |input.containers[1].volume_ids[1]| "vol3")))
(assert |defined_input.containers[1].volume_ids[0]|)
(assert (=> (and |defined_input.containers[1].volume_ids[0]|
         |defined_input.containers[1].volume_ids[1]|)
    (not (= |input.containers[1].volume_ids[0]|
            |input.containers[1].volume_ids[1]|))))
(assert |defined_input.containers[1].name|)
(assert |defined_input.containers[1].privileged|)
(assert |defined_input.containers[1].host_id|)
(assert |defined_input.containers[1].volume_ids|)
(assert (or (= |input.containers[2].host_id| "host1")
    (= |input.containers[2].host_id| "host2")
    (= |input.containers[2].host_id| "host3")))
(assert (or (= |input.containers[2].name| "web")
    (= |input.containers[2].name| "api")
    (= |input.containers[2].name| "worker")))
(assert (or (= |input.containers[2].volume_ids[0]| "vol1")
    (= |input.containers[2].volume_ids[0]| "vol2")
    (= |input.containers[2].volume_ids[0]| "vol3")))
(assert (or (= |input.containers[2].volume_ids[1]| "vol1")
    (= |input.containers[2].volume_ids[1]| "vol2")
    (= |input.containers[2].volume_ids[1]| "vol3")))
(assert |defined_input.containers[2].volume_ids[0]|)
(assert (=> (and |defined_input.containers[2].volume_ids[0]|
         |defined_input.containers[2].volume_ids[1]|)
    (not (= |input.containers[2].volume_ids[0]|
            |input.containers[2].volume_ids[1]|))))
(assert |defined_input.containers[2].name|)
(assert |defined_input.containers[2].privileged|)
(assert |defined_input.containers[2].host_id|)
(assert |defined_input.containers[2].volume_ids|)
(assert |defined_input.containers[0].name|)
(assert |defined_input.containers[0].privileged|)
(assert |defined_input.containers[0].host_id|)
(assert |defined_input.containers[0].volume_ids|)
(assert (=> (and |defined_input.containers[0].name| |defined_input.containers[1].name|)
    (not (= |input.containers[0].name| |input.containers[1].name|))))
(assert (=> (and |defined_input.containers[0].name| |defined_input.containers[2].name|)
    (not (= |input.containers[0].name| |input.containers[2].name|))))
(assert (=> (and |defined_input.containers[1].name| |defined_input.containers[2].name|)
    (not (= |input.containers[1].name| |input.containers[2].name|))))
(assert (or (= |input.hosts[0].id| "host1")
    (= |input.hosts[0].id| "host2")
    (= |input.hosts[0].id| "host3")))
(assert |defined_input.hosts[0].id|)
(assert |defined_input.hosts[0].public|)
(assert (or (= |input.hosts[1].id| "host1")
    (= |input.hosts[1].id| "host2")
    (= |input.hosts[1].id| "host3")))
(assert |defined_input.hosts[1].id|)
(assert |defined_input.hosts[1].public|)
(assert (or (= |input.hosts[2].id| "host1")
    (= |input.hosts[2].id| "host2")
    (= |input.hosts[2].id| "host3")))
(assert |defined_input.hosts[2].id|)
(assert |defined_input.hosts[2].public|)
(assert |defined_input.hosts[0].id|)
(assert |defined_input.hosts[0].public|)
(assert (=> (and |defined_input.hosts[0].id| |defined_input.hosts[1].id|)
    (not (= |input.hosts[0].id| |input.hosts[1].id|))))
(assert (=> (and |defined_input.hosts[0].id| |defined_input.hosts[2].id|)
    (not (= |input.hosts[0].id| |input.hosts[2].id|))))
(assert (=> (and |defined_input.hosts[1].id| |defined_input.hosts[2].id|)
    (not (= |input.hosts[1].id| |input.hosts[2].id|))))
(assert (or (= |input.volumes[0].id| "vol1")
    (= |input.volumes[0].id| "vol2")
    (= |input.volumes[0].id| "vol3")))
(assert |defined_input.volumes[0].id|)
(assert |defined_input.volumes[0].encrypted|)
(assert (or (= |input.volumes[1].id| "vol1")
    (= |input.volumes[1].id| "vol2")
    (= |input.volumes[1].id| "vol3")))
(assert |defined_input.volumes[1].id|)
(assert |defined_input.volumes[1].encrypted|)
(assert (or (= |input.volumes[2].id| "vol1")
    (= |input.volumes[2].id| "vol2")
    (= |input.volumes[2].id| "vol3")))
(assert |defined_input.volumes[2].id|)
(assert |defined_input.volumes[2].encrypted|)
(assert |defined_input.volumes[0].id|)
(assert |defined_input.volumes[0].encrypted|)
(assert (=> (and |defined_input.volumes[0].id| |defined_input.volumes[1].id|)
    (not (= |input.volumes[0].id| |input.volumes[1].id|))))
(assert (=> (and |defined_input.volumes[0].id| |defined_input.volumes[2].id|)
    (not (= |input.volumes[0].id| |input.volumes[2].id|))))
(assert (=> (and |defined_input.volumes[1].id| |defined_input.volumes[2].id|)
    (not (= |input.volumes[1].id| |input.volumes[2].id|))))
(assert defined_input.containers)
(assert defined_input.hosts)
(assert defined_input.volumes)
(assert (and true true))
(assert (let ((a!1 (and true
                (and true |defined_input.containers[0]|)
                |defined_input.volumes[0]|
                |defined_input.containers[0].volume_ids|
                |defined_input.volumes[0].id|
                (or (and |defined_input.containers[0].volume_ids[1]|
                         (= |input.containers[0].volume_ids[1]|
                            |input.volumes[0].id|))
                    (and |defined_input.containers[0].volume_ids[0]|
                         (= |input.containers[0].volume_ids[0]|
                            |input.volumes[0].id|)))
                (and |defined_input.volumes[0].encrypted|
                     (= |input.volumes[0].encrypted| false))
                |defined_input.containers[0]|
                |defined_input.containers[0]|))
      (a!2 (and true
                (and true |defined_input.containers[0]|)
                |defined_input.volumes[1]|
                |defined_input.containers[0].volume_ids|
                |defined_input.volumes[1].id|
                (or (and |defined_input.containers[0].volume_ids[1]|
                         (= |input.containers[0].volume_ids[1]|
                            |input.volumes[1].id|))
                    (and |defined_input.containers[0].volume_ids[0]|
                         (= |input.containers[0].volume_ids[0]|
                            |input.volumes[1].id|)))
                (and |defined_input.volumes[1].encrypted|
                     (= |input.volumes[1].encrypted| false))
                |defined_input.containers[0]|
                |defined_input.containers[0]|))
      (a!3 (and true
                (and true |defined_input.containers[0]|)
                |defined_input.volumes[2]|
                |defined_input.containers[0].volume_ids|
                |defined_input.volumes[2].id|
                (or (and |defined_input.containers[0].volume_ids[1]|
                         (= |input.containers[0].volume_ids[1]|
                            |input.volumes[2].id|))
                    (and |defined_input.containers[0].volume_ids[0]|
                         (= |input.containers[0].volume_ids[0]|
                            |input.volumes[2].id|)))
                (and |defined_input.volumes[2].encrypted|
                     (= |input.volumes[2].encrypted| false))
                |defined_input.containers[0]|
                |defined_input.containers[0]|))
      (a!5 (and true
                (and true |defined_input.containers[1]|)
                |defined_input.volumes[0]|
                |defined_input.containers[1].volume_ids|
                |defined_input.volumes[0].id|
                (or (and |defined_input.containers[1].volume_ids[0]|
                         (= |input.containers[1].volume_ids[0]|
                            |input.volumes[0].id|))
                    (and |defined_input.containers[1].volume_ids[1]|
                         (= |input.containers[1].volume_ids[1]|
                            |input.volumes[0].id|)))
                (and |defined_input.volumes[0].encrypted|
                     (= |input.volumes[0].encrypted| false))
                |defined_input.containers[1]|
                |defined_input.containers[1]|))
      (a!6 (and true
                (and true |defined_input.containers[1]|)
                |defined_input.volumes[1]|
                |defined_input.containers[1].volume_ids|
                |defined_input.volumes[1].id|
                (or (and |defined_input.containers[1].volume_ids[0]|
                         (= |input.containers[1].volume_ids[0]|
                            |input.volumes[1].id|))
                    (and |defined_input.containers[1].volume_ids[1]|
                         (= |input.containers[1].volume_ids[1]|
                            |input.volumes[1].id|)))
                (and |defined_input.volumes[1].encrypted|
                     (= |input.volumes[1].encrypted| false))
                |defined_input.containers[1]|
                |defined_input.containers[1]|))
      (a!7 (and true
                (and true |defined_input.containers[1]|)
                |defined_input.volumes[2]|
                |defined_input.containers[1].volume_ids|
                |defined_input.volumes[2].id|
                (or (and |defined_input.containers[1].volume_ids[0]|
                         (= |input.containers[1].volume_ids[0]|
                            |input.volumes[2].id|))
                    (and |defined_input.containers[1].volume_ids[1]|
                         (= |input.containers[1].volume_ids[1]|
                            |input.volumes[2].id|)))
                (and |defined_input.volumes[2].encrypted|
                     (= |input.volumes[2].encrypted| false))
                |defined_input.containers[1]|
                |defined_input.containers[1]|))
      (a!9 (and true
                (and true |defined_input.containers[2]|)
                |defined_input.volumes[0]|
                |defined_input.containers[2].volume_ids|
                |defined_input.volumes[0].id|
                (or (and |defined_input.containers[2].volume_ids[1]|
                         (= |input.containers[2].volume_ids[1]|
                            |input.volumes[0].id|))
                    (and |defined_input.containers[2].volume_ids[0]|
                         (= |input.containers[2].volume_ids[0]|
                            |input.volumes[0].id|)))
                (and |defined_input.volumes[0].encrypted|
                     (= |input.volumes[0].encrypted| false))
                |defined_input.containers[2]|
                |defined_input.containers[2]|))
      (a!10 (and true
                 (and true |defined_input.containers[2]|)
                 |defined_input.volumes[1]|
                 |defined_input.containers[2].volume_ids|
                 |defined_input.volumes[1].id|
                 (or (and |defined_input.containers[2].volume_ids[1]|
                          (= |input.containers[2].volume_ids[1]|
                             |input.volumes[1].id|))
                     (and |defined_input.containers[2].volume_ids[0]|
                          (= |input.containers[2].volume_ids[0]|
                             |input.volumes[1].id|)))
                 (and |defined_input.volumes[1].encrypted|
                      (= |input.volumes[1].encrypted| false))
                 |defined_input.containers[2]|
                 |defined_input.containers[2]|))
      (a!11 (and true
                 (and true |defined_input.containers[2]|)
                 |defined_input.volumes[2]|
                 |defined_input.containers[2].volume_ids|
                 |defined_input.volumes[2].id|
                 (or (and |defined_input.containers[2].volume_ids[1]|
                          (= |input.containers[2].volume_ids[1]|
                             |input.volumes[2].id|))
                     (and |defined_input.containers[2].volume_ids[0]|
                          (= |input.containers[2].volume_ids[0]|
                             |input.volumes[2].id|)))
                 (and |defined_input.volumes[2].encrypted|
                      (= |input.volumes[2].encrypted| false))
                 |defined_input.containers[2]|
                 |defined_input.containers[2]|)))
(let ((a!4 (or (and (and true |defined_input.containers[0]|)
                    |defined_input.containers[0].privileged|
                    (= |input.containers[0].privileged| true)
                    |defined_input.containers[0].name|)
               (and a!1
                    |defined_input.hosts[0]|
                    (and |defined_input.hosts[0].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[0].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[0].public|
                         (= |input.hosts[0].public| true))
                    |defined_input.containers[0].name|)
               (and a!1
                    |defined_input.hosts[1]|
                    (and |defined_input.hosts[1].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[1].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[1].public|
                         (= |input.hosts[1].public| true))
                    |defined_input.containers[0].name|)
               (and a!1
                    |defined_input.hosts[2]|
                    (and |defined_input.hosts[2].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[2].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[2].public|
                         (= |input.hosts[2].public| true))
                    |defined_input.containers[0].name|)
               (and a!2
                    |defined_input.hosts[0]|
                    (and |defined_input.hosts[0].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[0].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[0].public|
                         (= |input.hosts[0].public| true))
                    |defined_input.containers[0].name|)
               (and a!2
                    |defined_input.hosts[1]|
                    (and |defined_input.hosts[1].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[1].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[1].public|
                         (= |input.hosts[1].public| true))
                    |defined_input.containers[0].name|)
               (and a!2
                    |defined_input.hosts[2]|
                    (and |defined_input.hosts[2].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[2].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[2].public|
                         (= |input.hosts[2].public| true))
                    |defined_input.containers[0].name|)
               (and a!3
                    |defined_input.hosts[0]|
                    (and |defined_input.hosts[0].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[0].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[0].public|
                         (= |input.hosts[0].public| true))
                    |defined_input.containers[0].name|)
               (and a!3
                    |defined_input.hosts[1]|
                    (and |defined_input.hosts[1].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[1].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[1].public|
                         (= |input.hosts[1].public| true))
                    |defined_input.containers[0].name|)
               (and a!3
                    |defined_input.hosts[2]|
                    (and |defined_input.hosts[2].id|
                         |defined_input.containers[0].host_id|
                         (= |input.hosts[2].id| |input.containers[0].host_id|))
                    (and |defined_input.hosts[2].public|
                         (= |input.hosts[2].public| true))
                    |defined_input.containers[0].name|)))
      (a!8 (or (and (and true |defined_input.containers[1]|)
                    |defined_input.containers[1].privileged|
                    (= |input.containers[1].privileged| true)
                    |defined_input.containers[1].name|)
               (and a!5
                    |defined_input.hosts[0]|
                    (and |defined_input.hosts[0].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[0].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[0].public|
                         (= |input.hosts[0].public| true))
                    |defined_input.containers[1].name|)
               (and a!5
                    |defined_input.hosts[1]|
                    (and |defined_input.hosts[1].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[1].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[1].public|
                         (= |input.hosts[1].public| true))
                    |defined_input.containers[1].name|)
               (and a!5
                    |defined_input.hosts[2]|
                    (and |defined_input.hosts[2].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[2].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[2].public|
                         (= |input.hosts[2].public| true))
                    |defined_input.containers[1].name|)
               (and a!6
                    |defined_input.hosts[0]|
                    (and |defined_input.hosts[0].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[0].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[0].public|
                         (= |input.hosts[0].public| true))
                    |defined_input.containers[1].name|)
               (and a!6
                    |defined_input.hosts[1]|
                    (and |defined_input.hosts[1].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[1].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[1].public|
                         (= |input.hosts[1].public| true))
                    |defined_input.containers[1].name|)
               (and a!6
                    |defined_input.hosts[2]|
                    (and |defined_input.hosts[2].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[2].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[2].public|
                         (= |input.hosts[2].public| true))
                    |defined_input.containers[1].name|)
               (and a!7
                    |defined_input.hosts[0]|
                    (and |defined_input.hosts[0].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[0].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[0].public|
                         (= |input.hosts[0].public| true))
                    |defined_input.containers[1].name|)
               (and a!7
                    |defined_input.hosts[1]|
                    (and |defined_input.hosts[1].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[1].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[1].public|
                         (= |input.hosts[1].public| true))
                    |defined_input.containers[1].name|)
               (and a!7
                    |defined_input.hosts[2]|
                    (and |defined_input.hosts[2].id|
                         |defined_input.containers[1].host_id|
                         (= |input.hosts[2].id| |input.containers[1].host_id|))
                    (and |defined_input.hosts[2].public|
                         (= |input.hosts[2].public| true))
                    |defined_input.containers[1].name|)))
      (a!12 (or (and (and true |defined_input.containers[2]|)
                     |defined_input.containers[2].privileged|
                     (= |input.containers[2].privileged| true)
                     |defined_input.containers[2].name|)
                (and a!9
                     |defined_input.hosts[0]|
                     (and |defined_input.hosts[0].id|
                          |defined_input.containers[2].host_id|
                          (= |input.hosts[0].id| |input.containers[2].host_id|))
                     (and |defined_input.hosts[0].public|
                          (= |input.hosts[0].public| true))
                     |defined_input.containers[2].name|)
                (and a!9
                     |defined_input.hosts[1]|
                     (and |defined_input.hosts[1].id|
                          |defined_input.containers[2].host_id|
                          (= |input.hosts[1].id| |input.containers[2].host_id|))
                     (and |defined_input.hosts[1].public|
                          (= |input.hosts[1].public| true))
                     |defined_input.containers[2].name|)
                (and a!9
                     |defined_input.hosts[2]|
                     (and |defined_input.hosts[2].id|
                          |defined_input.containers[2].host_id|
                          (= |input.hosts[2].id| |input.containers[2].host_id|))
                     (and |defined_input.hosts[2].public|
                          (= |input.hosts[2].public| true))
                     |defined_input.containers[2].name|)
                (and a!10
                     |defined_input.hosts[0]|
                     (and |defined_input.hosts[0].id|
                          |defined_input.containers[2].host_id|
                          (= |input.hosts[0].id| |input.containers[2].host_id|))
                     (and |defined_input.hosts[0].public|
                          (= |input.hosts[0].public| true))
                     |defined_input.containers[2].name|)
                (and a!10
                     |defined_input.hosts[1]|
                     (and |defined_input.hosts[1].id|
                          |defined_input.containers[2].host_id|
                          (= |input.hosts[1].id| |input.containers[2].host_id|))
                     (and |defined_input.hosts[1].public|
                          (= |input.hosts[1].public| true))
                     |defined_input.containers[2].name|)
                (and a!10
                     |defined_input.hosts[2]|
                     (and |defined_input.hosts[2].id|
                          |defined_input.containers[2].host_id|
                          (= |input.hosts[2].id| |input.containers[2].host_id|))
                     (and |defined_input.hosts[2].public|
                          (= |input.hosts[2].public| true))
                     |defined_input.containers[2].name|)
                (and a!11
                     |defined_input.hosts[0]|
                     (and |defined_input.hosts[0].id|
                          |defined_input.containers[2].host_id|
                          (= |input.hosts[0].id| |input.containers[2].host_id|))
                     (and |defined_input.hosts[0].public|
                          (= |input.hosts[0].public| true))
                     |defined_input.containers[2].name|)
                (and a!11
                     |defined_input.hosts[1]|
                     (and |defined_input.hosts[1].id|
                          |defined_input.containers[2].host_id|
                          (= |input.hosts[1].id| |input.containers[2].host_id|))
                     (and |defined_input.hosts[1].public|
                          (= |input.hosts[1].public| true))
                     |defined_input.containers[2].name|)
                (and a!11
                     |defined_input.hosts[2]|
                     (and |defined_input.hosts[2].id|
                          |defined_input.containers[2].host_id|
                          (= |input.hosts[2].id| |input.containers[2].host_id|))
                     (and |defined_input.hosts[2].public|
                          (= |input.hosts[2].public| true))
                     |defined_input.containers[2].name|))))
(let ((a!13 (and true
                 (= (+ 0 (ite a!4 1 0) (ite a!8 1 0) (ite a!12 1 0)) 0)
                 true)))
  (= (ite a!13 true false) false)))))
(assert (and true
     true
     true
     true
     true
     |defined_input.containers[2]|
     |defined_input.volumes[2]|
     |defined_input.containers[2].volume_ids|
     |defined_input.volumes[2].id|
     (or (and |defined_input.containers[2].volume_ids[1]|
              (= |input.containers[2].volume_ids[1]| |input.volumes[2].id|))
         (and |defined_input.containers[2].volume_ids[0]|
              (= |input.containers[2].volume_ids[0]| |input.volumes[2].id|)))
     |defined_input.volumes[2].encrypted|
     (= |input.volumes[2].encrypted| false)
     |defined_input.containers[2]|
     |defined_input.containers[2]|
     |defined_input.hosts[2]|
     |defined_input.hosts[2].id|
     |defined_input.containers[2].host_id|
     (= |input.hosts[2].id| |input.containers[2].host_id|)
     |defined_input.hosts[2].public|
     (= |input.hosts[2].public| true)))
(assert (not (and true
          true
          true
          true
          |defined_input.containers[2]|
          |defined_input.containers[2].privileged|
          (= |input.containers[2].privileged| true))))
