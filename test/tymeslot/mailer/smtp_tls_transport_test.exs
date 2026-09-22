defmodule Tymeslot.Mailer.SMTPTlsTransportTest do
  @moduledoc """
  Drives a real TLS handshake through gen_smtp using the configuration
  `Tymeslot.Mailer.SMTPConfig` produces.

  The port-465 regression these tests guard was invisible at the
  configuration layer: the keyword list looked correct, and gen_smtp silently
  ignored half of it. Only an actual connection distinguishes the two.
  """

  use ExUnit.Case, async: true

  @moduletag :mailer
  @moduletag :integration

  alias Tymeslot.Mailer.{SMTPAdapter, SMTPConfig}

  # Generous on purpose. A tight budget here does not test anything: the
  # relay is an ordinary Erlang process, and if the suite is busy enough that
  # it is not scheduled into `:ssl.transport_accept/2` before the client gives
  # up, the client fails with `{:network_failure, _host, {:error, :timeout}}` —
  # indistinguishable from the relay refusing the certificate, and green or red
  # depending on machine load. Every outcome under test (a completed handshake,
  # a TLS alert) is reached in milliseconds once both sides are running, so
  # nothing waits for this bound except a genuine stall.
  @timeout 30_000

  # Certificate generation is the expensive part of this module — four RSA-2048
  # keypairs per chain — so both chains are built once for the module rather
  # than per test. Beyond the runtime saved, it keeps that work out of the
  # window in which the relay has to be scheduled.
  setup_all do
    %{
      trusted: relay_certificates(~c"localhost"),
      mismatched: relay_certificates(~c"elsewhere.example.com")
    }
  end

  describe "implicit TLS (port 465)" do
    test "connects when the relay's certificate chains to a trusted CA", %{trusted: certs} do
      relay = start_tls_relay(certs)

      assert {:ok, socket} = open(relay, cacertfile: relay.cacertfile)
      :gen_smtp_client.close(socket)
    end

    test "connects to an untrusted relay when verification is disabled", %{trusted: certs} do
      relay = start_tls_relay(certs)

      assert {:ok, socket} = open(relay, tls_verify: :none)
      :gen_smtp_client.close(socket)
    end

    test "rejects a relay no trust store validates", %{trusted: certs} do
      relay = start_tls_relay(certs)

      # A TLS alert, specifically: before the `:sockopts` fix this failed with
      # `{:options, :incompatible, [verify: :verify_peer, cacerts: :undefined]}`,
      # never reaching the certificate at all.
      assert {:error, :retries_exceeded,
              {:network_failure, _host, {:error, {:tls_alert, _alert}}}} = open(relay, [])
    end

    test "rejects a trusted CA's certificate issued for a different hostname", %{
      mismatched: certs
    } do
      relay = start_tls_relay(certs)

      assert {:error, :retries_exceeded,
              {:network_failure, _host, {:error, {:tls_alert, _alert}}}} =
               open(relay, cacertfile: relay.cacertfile)
    end
  end

  describe "a TLS 1.3 relay that omits the middlebox ChangeCipherSpec" do
    setup %{trusted: certs} do
      %{relay: certs |> start_tls_relay(versions: [:"tlsv1.3"]) |> without_middlebox_record()}
    end

    test "aborts the handshake under the configuration a send starts from", %{relay: relay} do
      # OTP's client asserts the record it was never promised, so the session
      # fails before any message is sent — and gen_smtp reports only that TLS
      # failed, which is why the adapter cannot tell this relay from a broken
      # certificate without trying.
      assert {:error, :retries_exceeded,
              {:network_failure, _host, {:error, {:tls_alert, {:unexpected_message, _detail}}}}} =
               open(relay, cacertfile: relay.cacertfile)
    end

    @tag :capture_log
    test "delivers once the adapter retries without the compatibility mode", %{relay: relay} do
      assert {:ok, _receipt} =
               SMTPAdapter.deliver(email(), config(relay, cacertfile: relay.cacertfile))
    end
  end

  describe "a STARTTLS relay that omits the middlebox ChangeCipherSpec" do
    # The production path: port 587, where gen_smtp reports nothing but
    # `:tls_failed` — the same relay behaviour, a different error shape, and
    # the one the adapter's retry was written for.
    setup %{trusted: certs} do
      %{
        relay: certs |> start_starttls_relay(versions: [:"tlsv1.3"]) |> without_middlebox_record()
      }
    end

    test "fails the upgrade under the configuration a send starts from", %{relay: relay} do
      config = starttls_config(relay, cacertfile: relay.cacertfile)

      assert {:error, :retries_exceeded, {:temporary_failure, _host, :tls_failed}} =
               config |> Keyword.drop([:adapter]) |> :gen_smtp_client.open()
    end

    @tag :capture_log
    test "delivers once the adapter retries without the compatibility mode", %{relay: relay} do
      assert {:ok, _receipt} =
               SMTPAdapter.deliver(email(), starttls_config(relay, cacertfile: relay.cacertfile))
    end
  end

  defp email do
    Swoosh.Email.new(
      from: {"Tymeslot", "no-reply@example.com"},
      to: {"Booker", "booker@example.com"},
      subject: "Reminder",
      text_body: "See you tomorrow."
    )
  end

  # Builds the real production configuration for a port-465 relay, then points
  # it at the ephemeral test listener. Only the port and the credentials-free
  # dialogue are test scaffolding; every TLS option under test is the one
  # `SMTPConfig` produced.
  defp open(relay, extra) do
    relay
    |> config(extra)
    |> Keyword.drop([:adapter])
    |> :gen_smtp_client.open()
  end

  defp config(relay, extra), do: build_config(relay, [port: 465] ++ extra)

  # Port 587: `SMTPConfig` reads it as plain TCP upgraded with STARTTLS, which
  # is where a real relay's TLS failure loses its alert on the way out.
  defp starttls_config(relay, extra), do: build_config(relay, [port: 587] ++ extra)

  defp build_config(relay, extra) do
    [host: "localhost", username: "user", password: "pass"]
    |> Keyword.merge(extra)
    |> SMTPConfig.build()
    |> Keyword.merge(
      port: relay.port,
      auth: :never,
      retries: 0,
      timeout: @timeout,
      session_timeout: @timeout
    )
  end

  defp relay_certificates(dns_name) do
    %{cert: cert, key: key, cacerts: cacerts} = certificates(dns_name)

    %{cert: cert, key: key, cacertfile: write_cacertfile(cacerts)}
  end

  defp start_tls_relay(certs, extra \\ [])

  defp start_tls_relay(%{cert: cert, key: key, cacertfile: cacertfile}, extra) do
    {:ok, listen} =
      :ssl.listen(
        0,
        [
          :binary,
          cert: cert,
          key: key,
          active: false,
          packet: :line,
          reuseaddr: true
        ] ++ extra
      )

    {:ok, {_address, port}} = :ssl.sockname(listen)
    # Unlinked: a relay that dies mid-handshake must fail the assertion under
    # test, not take the test process down with it.
    spawn(fn -> serve(listen) end)
    on_exit(fn -> :ssl.close(listen) end)

    %{port: port, cacertfile: cacertfile}
  end

  # The dummy ChangeCipherSpec of RFC 8446 appendix D.4, as it goes over the
  # wire: a plaintext record of one byte, sent right after the ServerHello.
  @middlebox_record <<20, 3, 3, 0, 1, 1>>

  # Puts the relay behind a proxy that drops that record on its way to the
  # client, which is what the client sees from a TLS 1.3 server that never
  # sends it. An OTP server cannot stand in here: it answers a client that
  # asked for compatibility mode with the record whatever its own
  # `middlebox_comp_mode` says, so the bug never appears.
  defp without_middlebox_record(relay) do
    {:ok, listen} =
      :gen_tcp.listen(0, [:binary, active: false, packet: :raw, reuseaddr: true])

    {:ok, port} = :inet.port(listen)
    spawn(fn -> proxy_accept(listen, relay.port) end)
    on_exit(fn -> :gen_tcp.close(listen) end)

    %{relay | port: port}
  end

  defp proxy_accept(listen, upstream_port) do
    with {:ok, client} <- :gen_tcp.accept(listen, @timeout),
         {:ok, upstream} <-
           :gen_tcp.connect(~c"localhost", upstream_port, [:binary, active: false, packet: :raw]) do
      spawn(fn -> pump(client, upstream, :verbatim) end)
      spawn(fn -> pump(upstream, client, :strip_middlebox_record) end)
      proxy_accept(listen, upstream_port)
    end
  end

  defp pump(from, to, mode) do
    case :gen_tcp.recv(from, 0, @timeout) do
      {:ok, data} ->
        {payload, next} = forward(data, mode)
        :gen_tcp.send(to, payload)
        pump(from, to, next)

      {:error, _closed} ->
        :gen_tcp.close(to)
    end
  end

  # Only the first occurrence is dropped, and nothing is inspected afterwards:
  # the compatibility record is sent once, in the clear, before any encrypted
  # traffic could coincidentally carry the same six bytes.
  defp forward(data, :strip_middlebox_record) do
    case :binary.split(data, @middlebox_record) do
      [before, rest] -> {before <> rest, :verbatim}
      [whole] -> {whole, :strip_middlebox_record}
    end
  end

  defp forward(data, :verbatim), do: {data, :verbatim}

  defp start_starttls_relay(%{cert: cert, key: key, cacertfile: cacertfile}, extra) do
    {:ok, listen} =
      :gen_tcp.listen(0, [:binary, active: false, packet: :line, reuseaddr: true])

    {:ok, port} = :inet.port(listen)
    spawn(fn -> serve_starttls(listen, [cert: cert, key: key] ++ extra) end)
    on_exit(fn -> :gen_tcp.close(listen) end)

    %{port: port, cacertfile: cacertfile}
  end

  defp serve_starttls(listen, ssl_options) do
    with {:ok, socket} <- :gen_tcp.accept(listen, @timeout) do
      :gen_tcp.send(socket, "220 localhost ESMTP test\r\n")
      starttls_dialogue(socket, ssl_options)
      serve_starttls(listen, ssl_options)
    end
  end

  defp starttls_dialogue(socket, ssl_options) do
    case :gen_tcp.recv(socket, 0, @timeout) do
      {:ok, "EHLO" <> _rest} ->
        :gen_tcp.send(socket, "250-localhost\r\n250 STARTTLS\r\n")
        starttls_dialogue(socket, ssl_options)

      {:ok, "STARTTLS" <> _rest} ->
        :gen_tcp.send(socket, "220 Ready to start TLS\r\n")
        upgrade(socket, ssl_options)

      {:ok, _other} ->
        :gen_tcp.send(socket, "250 OK\r\n")
        starttls_dialogue(socket, ssl_options)

      {:error, _reason} ->
        :ok
    end
  end

  defp upgrade(socket, ssl_options) do
    case :ssl.handshake(socket, [packet: :line] ++ ssl_options, @timeout) do
      {:ok, connection} -> dialogue(connection)
      {:error, _refused} -> :gen_tcp.close(socket)
    end
  end

  # Serves one connection at a time until the listener closes, rather than
  # exiting after the first: a client whose handshake is refused reconnects to
  # try something else, and a relay that has already gone would fail that
  # second attempt for the wrong reason.
  defp serve(listen) do
    with {:ok, socket} <- :ssl.transport_accept(listen, @timeout) do
      case :ssl.handshake(socket, @timeout) do
        {:ok, connection} ->
          :ssl.send(connection, "220 localhost ESMTP test\r\n")
          dialogue(connection)

        {:error, _refused} ->
          :ok
      end

      serve(listen)
    end
  end

  defp dialogue(connection) do
    case :ssl.recv(connection, 0, @timeout) do
      {:ok, "EHLO" <> _rest} ->
        :ssl.send(connection, "250-localhost\r\n250 SIZE 10240000\r\n")
        dialogue(connection)

      {:ok, "DATA" <> _rest} ->
        :ssl.send(connection, "354 End data with <CR><LF>.<CR><LF>\r\n")
        read_message(connection)
        :ssl.send(connection, "250 OK: queued as test\r\n")
        dialogue(connection)

      {:ok, "QUIT" <> _rest} ->
        :ssl.send(connection, "221 Bye\r\n")
        :ssl.close(connection)

      {:ok, _other} ->
        :ssl.send(connection, "250 OK\r\n")
        dialogue(connection)

      {:error, _reason} ->
        :ok
    end
  end

  # Swallows the message body, which ends on the lone dot of RFC 5321 §4.1.1.4.
  defp read_message(connection) do
    case :ssl.recv(connection, 0, @timeout) do
      {:ok, ".\r\n"} -> :ok
      {:ok, _line} -> read_message(connection)
      {:error, _reason} -> :ok
    end
  end

  # `:public_key.pkix_test_data/1` issues a throwaway CA and a leaf signed by
  # it, so the trusted and untrusted cases differ only in whether the client is
  # given the CA — no fixture files, no openssl binary.
  #
  # RSA/SHA-256 is specified rather than taken as the default: the default
  # chain is rejected outright by a TLS 1.3 server with
  # `unable_to_supply_acceptable_cert`, which would make every connection fail
  # and quietly turn the two rejection tests below green for the wrong reason.
  @key_params [key: {:rsa, 2048, 65_537}, digest: :sha256]

  defp certificates(dns_name) do
    subject_alt_name = {:Extension, {2, 5, 29, 17}, false, [dNSName: dns_name]}

    config =
      :public_key.pkix_test_data(%{
        server_chain: %{
          root: @key_params,
          intermediates: [],
          peer: @key_params ++ [extensions: [subject_alt_name]]
        },
        client_chain: %{root: @key_params, intermediates: [], peer: @key_params}
      })

    server = config[:server_config]
    %{cert: server[:cert], key: server[:key], cacerts: server[:cacerts]}
  end

  defp write_cacertfile(cacerts) do
    path =
      Path.join(System.tmp_dir!(), "tymeslot-test-ca-#{System.unique_integer([:positive])}.pem")

    pem = :public_key.pem_encode(Enum.map(cacerts, &{:Certificate, &1, :not_encrypted}))

    File.write!(path, pem)
    on_exit(fn -> File.rm(path) end)

    path
  end
end
