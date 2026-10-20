defmodule Tymeslot.Integrations.Calendar.IcsGeneratorItipTest do
  # Mutates the :email application env, so it cannot run alongside the other
  # ICS tests.
  use Tymeslot.DataCase, async: false
  @moduletag :integrations

  import Swoosh.Email, except: [from: 2]

  alias Tymeslot.Integrations.Calendar.IcsGenerator

  @details %{
    title: "Meeting",
    start_time: ~U[2026-01-15 14:00:00Z],
    end_time: ~U[2026-01-15 15:00:00Z],
    uid: "meeting-123",
    organizer_email: "organizer@example.com",
    organizer_name: "Olga Organiser",
    attendee_email: "jane@example.com",
    attendee_name: "Jane Doe"
  }

  setup do
    original = Application.get_env(:tymeslot, :email)
    on_exit(fn -> Application.put_env(:tymeslot, :email, original) end)
    :ok
  end

  defp unfold(ics), do: String.replace(ics, "\r\n ", "")

  defp set_ics_method(method) do
    email_config = Application.get_env(:tymeslot, :email)
    Application.put_env(:tymeslot, :email, Keyword.put(email_config, :ics_method, method))
  end

  describe "EMAIL_ICS_METHOD=request" do
    setup do
      set_ics_method(:request)
      :ok
    end

    test "an invitation is an iTIP REQUEST, marked as one on the MIME part" do
      attachment = IcsGenerator.generate_ics_attachment(@details)

      assert attachment.data =~ "METHOD:REQUEST"
      refute attachment.data =~ "METHOD:PUBLISH"
      refute attachment.data =~ "SCHEDULE-AGENT"
      assert attachment.data =~ "STATUS:CONFIRMED"
      refute attachment.data =~ ~r/[^\r]\n/

      assert unfold(attachment.data) =~
               ~s(ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=ACCEPTED;RSVP=FALSE;CN="Jane Doe":)

      assert attachment.data =~ ~s(ORGANIZER;CN="Olga Organiser":mailto:organizer@example.com)

      assert [{"Content-Type", content_type}] = attachment.headers
      assert content_type =~ "text/calendar;"
      assert content_type =~ "method=REQUEST"
    end

    test "an update is a REQUEST carrying the given SEQUENCE" do
      attachment = IcsGenerator.generate_ics_update_attachment(@details, 2)

      assert attachment.data =~ "METHOD:REQUEST"
      assert attachment.data =~ "SEQUENCE:2"
    end

    test "a cancellation is an iTIP CANCEL" do
      attachment = IcsGenerator.generate_ics_cancel_attachment(@details, 3)

      assert attachment.data =~ "METHOD:CANCEL"
      assert attachment.data =~ "STATUS:CANCELLED"
      assert attachment.data =~ "SEQUENCE:3"
      assert [{"Content-Type", content_type}] = attachment.headers
      assert content_type =~ "method=CANCEL"
    end

    test "an organizer without a name still yields a valid property" do
      attachment =
        @details |> Map.delete(:organizer_name) |> IcsGenerator.generate_ics_attachment()

      assert attachment.data =~ "\r\nORGANIZER:mailto:organizer@example.com"
    end

    test "a guest's copy names the guest as a second attendee" do
      attachment =
        @details
        |> Map.put(:ics_guest, %{email: "greg@example.com", name: "Greg Guest"})
        |> IcsGenerator.generate_ics_attachment()

      ics = unfold(attachment.data)

      assert ics =~ ~s(CN="Jane Doe":mailto:jane@example.com)

      assert ics =~
               ~s(ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=ACCEPTED;RSVP=FALSE;CN="Greg Guest":mailto:greg@example.com)

      assert length(Regex.scan(~r/^ATTENDEE/m, ics)) == 2
    end

    test "a guest who is the booker is not listed twice" do
      attachment =
        @details
        |> Map.put(:ics_guest, %{email: "JANE@example.com", name: "Jane"})
        |> IcsGenerator.generate_ics_attachment()

      assert length(Regex.scan(~r/^ATTENDEE/m, unfold(attachment.data))) == 1
    end

    test "guest emails carry the guest in their calendar attachment" do
      details =
        Tymeslot.EmailTestHelpers.build_appointment_details(%{
          guest_name: "Greg Guest",
          guest_accept_url: "https://tymeslot.example.com/guest/tok/accept",
          guest_decline_url: "https://tymeslot.example.com/guest/tok/decline",
          original_start_time: ~U[2026-01-14 09:00:00Z],
          original_start_time_attendee_tz: ~U[2026-01-14 09:00:00Z],
          ical_sequence: 2
        })

      for {template, method} <- [
            {Tymeslot.Emails.Templates.AppointmentConfirmation, "REQUEST"},
            {Tymeslot.Emails.Templates.AppointmentRescheduled, "REQUEST"},
            {Tymeslot.Emails.Templates.AppointmentCancellation, "CANCEL"}
          ] do
        email = template.render(:guest, "greg@example.com", details)
        ics = Enum.find(email.attachments, &(&1.content_type == "text/calendar"))

        assert ics.data =~ "METHOD:#{method}", inspect(template)
        assert unfold(ics.data) =~ ~s(CN="Greg Guest":mailto:greg@example.com), inspect(template)
      end
    end

    test "the publish default never lists the guest" do
      set_ics_method(:publish)

      attachment =
        @details
        |> Map.put(:ics_guest, %{email: "greg@example.com", name: "Greg Guest"})
        |> IcsGenerator.generate_ics_attachment()

      refute attachment.data =~ "greg@example.com"
    end

    test "a payload without an attendee falls back to PUBLISH" do
      attachment =
        @details |> Map.delete(:attendee_email) |> IcsGenerator.generate_ics_attachment()

      assert attachment.data =~ "METHOD:PUBLISH"
      assert attachment.headers == []
    end

    test "the encoded email carries method=REQUEST on the text/calendar part" do
      attachment = IcsGenerator.generate_ics_attachment(@details, "en", "appointment-1.ics")

      raw =
        new()
        |> Swoosh.Email.from({"Tymeslot", "rdv@example.com"})
        |> to("jane@example.com")
        |> subject("Booked")
        |> text_body("text")
        |> html_body("<p>html</p>")
        |> attachment(attachment)
        |> Swoosh.Adapters.SMTP.Helpers.body([])

      [part] =
        raw
        |> String.split(~r/\r\n--/)
        |> Enum.filter(&(&1 =~ ~r/Content-Type: text\/calendar/i))

      [headers | _] = String.split(part, "\r\n\r\n", parts: 2)
      unfolded = String.replace(headers, ~r/\r\n[ \t]+/, " ")

      assert [content_type] =
               Regex.run(~r/^Content-Type: (.*)$/mi, unfolded, capture: :all_but_first)

      assert content_type =~ ~r/^text\/calendar;/
      assert content_type =~ "method=REQUEST"
      assert length(Regex.scan(~r/^Content-Type:/mi, unfolded)) == 1
      assert unfolded =~ ~r/Content-Disposition: attachment;.*filename="?appointment-1\.ics/i
    end
  end

  describe "default (publish)" do
    test "keeps METHOD:PUBLISH with a bare content type" do
      set_ics_method(:publish)
      attachment = IcsGenerator.generate_ics_attachment(@details)

      assert attachment.data =~ "METHOD:PUBLISH"
      assert attachment.data =~ "ORGANIZER;SCHEDULE-AGENT=CLIENT;CN="
      assert unfold(attachment.data) =~ "ATTENDEE;SCHEDULE-AGENT=CLIENT;CN="
      assert attachment.headers == []
    end
  end
end
