defmodule Authable.Authentication.TokenTest do
  use ExUnit.Case
  use Authable.Rollbackable
  use Authable.RepoCase
  import Authable.Factory
  alias Authable.Authentication.Token, as: TokenAuthentication

  @access_token_value "access_token_1234"
  @session_token_value "session_token_1234"

  setup do
    user = insert(:user)
    insert(:access_token, %{value: @access_token_value, user: user})
    insert(:session_token, %{value: @session_token_value, user: user})
    :ok
  end

  test "authorize with bearer token" do
    authorized_user = TokenAuthentication.authenticate({"access_token",
      @access_token_value}, [])
    refute is_nil(authorized_user)
  end

  test "authorize with session token" do
    authorized_user = TokenAuthentication.authenticate({"session_token",
      @session_token_value}, [])
    refute is_nil(authorized_user)
  end
end
